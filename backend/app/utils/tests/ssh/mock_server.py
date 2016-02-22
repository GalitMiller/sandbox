# -*- coding: utf-8 -*-

import base64

from threading import Thread, Event
from unipath import Path
from zope.interface import implements

from twisted.conch import avatar, error, recvline
from twisted.conch.insults import insults
from twisted.conch.interfaces import IConchUser, ISession
from twisted.conch.ssh import keys, factory, session
from twisted.cred import checkers, credentials, portal
from twisted.python import failure


class SSHMockProtocol(recvline.HistoricRecvLine):

    def __init__(self, user):
        self.user = user

    def connectionMade(self):
        recvline.HistoricRecvLine.connectionMade(self)
        self.terminal.write("Welcome to test SSH server!")
        self.terminal.nextLine()
        self.do_help()
        self.show_prompt()

    def lineReceived(self, line):
        line = line.strip()
        if line:
            cmd_and_args = line.split()
            cmd = cmd_and_args[0]
            args = cmd_and_args[1:]
            func = self.get_command_func(cmd)
            if func:
                try:
                    func(*args)
                except Exception, e:
                    self.terminal.write("Error: %s" % e)
                    self.terminal.nextLine()
            else:
                self.terminal.write("No such command.")
                self.terminal.nextLine()
        self.show_prompt()

    def show_prompt(self):
        self.terminal.write("$ ")

    def get_command_func(self, cmd):
        return getattr(self, 'do_' + cmd, None)

    def do_help(self):
        publicMethods = filter(
            lambda funcname: funcname.startswith('do_'),
            dir(self)
        )
        commands = [cmd.replace('do_', '', 1) for cmd in publicMethods]
        self.terminal.write("Commands: " + " ".join(commands))
        self.terminal.nextLine()

    def do_echo(self, *args):
        self.terminal.write(" ".join(args))
        self.terminal.nextLine()

    def do_whoami(self):
        self.terminal.write(self.user.username)
        self.terminal.nextLine()

    def do_quit(self):
        self.terminal.write("Good bye!")
        self.terminal.nextLine()
        self.terminal.loseConnection()

    def do_clear(self):
        self.terminal.reset()


class SSHMockAvatar(avatar.ConchUser):
    implements(ISession)

    def __init__(self, username):
        avatar.ConchUser.__init__(self)
        self.username = username
        self.channelLookup.update({'session': session.SSHSession})

    def openShell(self, protocol):
        serverProtocol = insults.ServerProtocol(SSHMockProtocol, self)
        serverProtocol.makeConnection(protocol)
        protocol.makeConnection(session.wrapProtocol(serverProtocol))

    def getPty(self, terminal, windowSize, attrs):
        return None

    def execCommand(self, protocol, cmd):
        if cmd:
            self.client = TransportWrapper(protocol)

            cmd_and_args = cmd.split()
            cmd, args = cmd_and_args[0], cmd_and_args[1:]
            func = self.get_exec_func(cmd)

            if func:
                try:
                    func(*args)
                except Exception as e:
                    self.client.write("Error: {0}".format(e))
            else:
                self.client.write("No such command.")

            self.client.loseConnection()
            protocol.session.conn.transport.expectedLoseConnection = 1

    def get_exec_func(self, cmd):
        return getattr(self, 'exec_' + cmd, None)

    def exec_whoami(self):
        self.client.write(self.username)

    def exec_echo(self, *args):
        self.client.write(" ".join(args))

    def eofReceived(self):
        pass

    def closed(self):
        pass


class TransportWrapper(object):

    def __init__(self, p):
        self.protocol = p
        p.makeConnection(self)
        self.closed = 0

    def write(self, data):
        self.protocol.outReceived(data)
        self.protocol.outReceived('\r\n')
        if '\x00' in data:  # mimic 'exit' for the shell test
            self.loseConnection()

    def loseConnection(self):
        if self.closed:
            return
        self.closed = 1
        self.protocol.inConnectionLost()
        self.protocol.outConnectionLost()
        self.protocol.errConnectionLost()


class SSHMockRealm(object):
    implements(portal.IRealm)

    def requestAvatar(self, avatarId, mind, *interfaces):
        if IConchUser in interfaces:
            return interfaces[0], SSHMockAvatar(avatarId), lambda: None
        else:
            raise NotImplementedError("No supported interfaces found.")


class PublicKeyCredentialsChecker(object):
    implements(checkers.ICredentialsChecker)
    credentialInterfaces = (credentials.ISSHPrivateKey,)

    def __init__(self, authorizedKeys):
        self.authorizedKeys = authorizedKeys

    def requestAvatarId(self, credentials):
        userKeyString = self.authorizedKeys.get(credentials.username)
        if not userKeyString:
            return failure.Failure(error.ConchError("No such user"))

        # Remove the 'ssh-rsa' type before decoding.
        if credentials.blob != base64.decodestring(userKeyString.split(" ")[1]):
            raise failure.failure(error.ConchError("I don't recognize that key"))

        if not credentials.signature:
            return failure.Failure(error.ValidPublicKey())

        user_key = keys.Key.fromString(data=userKeyString)
        if user_key.verify(credentials.signature, credentials.sigData):
            return credentials.username
        else:
            print("signature check failed")
            return failure.Failure(error.ConchError("Incorrect signature"))


def get_ssh_key(keys_path, name):
    with open(Path(keys_path).child(name)) as blob_file:
        blob = blob_file.read()
        return keys.Key.fromString(data=blob)


def get_ssh_public_key(keys_path, name):
    return get_ssh_key(keys_path, name + '.pub')


def get_both_ssh_keys(keys_path, name):
    return get_ssh_key(keys_path, name), get_ssh_public_key(keys_path, name)


def start_threaded_server(interface, port=0, username='root', keys_path='.'):
    from twisted.internet import reactor

    ssh_factory = factory.SSHFactory()
    ssh_factory.portal = portal.Portal(SSHMockRealm())

    # The server's keys
    private_key, public_key = get_both_ssh_keys(keys_path, 'mock-server')
    ssh_factory.publicKeys = {'ssh-rsa': public_key}
    ssh_factory.privateKeys = {'ssh-rsa': private_key}

    # Authorized client keys
    authorized_keys = {
        username: get_ssh_public_key(keys_path, username).toString('OPENSSH')
    }
    checker = PublicKeyCredentialsChecker(authorized_keys)
    ssh_factory.portal.registerChecker(checker)

    listen_event = Event()

    endpoint = reactor.listenTCP(port, ssh_factory, interface=interface)
    reactor.callWhenRunning(lambda: listen_event.set())
    Thread(target=reactor.run, args=(False, )).start()

    listen_event.wait()
    return endpoint.getHost()


def stop_threaded_server():
    from twisted.internet import reactor
    reactor.callFromThread(reactor.stop)
