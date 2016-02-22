angular.module('bricata.uicore.ipinput')
    .controller('ipInputController', ['$scope', 'IPsCollections',
        function ($scope, IPsCollections) {

            // List with IP addresses. Currently comes from the predefined service
            $scope.IPsCollections = IPsCollections;

            // Opening drop-down menu with IP addresses list
            $scope.toggleDropdown = function($event) {
                $event.preventDefault();
                $event.stopPropagation();
            };

            // Selecting IP address from the drop-down list
            $scope.selectIPAddress = function (ip) {
                $scope.selectedIpAddress.ip = ip.name;
            };

            // Select Port function from the Port list menu
             $scope.selectPort = function (port) {
                $scope.selectedPort.port = port.name;
             };

        }])
    .factory('IPsCollections', [function(){
        return {

            ipAddressesList: [
                {"name": 'HOME_NET', "address": '212.168.33.101'},
                {"name": 'Office', "address": '68.70.53.20'},
                {"name": 'Other', "address": '101.0.0.3'}
            ],

            portsList: [
                {"name": 'PORT_1', "value": '3000'},
                {"name": 'PORT_2', "value": '8080'},
                {"name": 'PORT_3', "value": '21'}
            ]

        };
    }]);
