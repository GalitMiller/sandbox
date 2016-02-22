describe('bricata ui configuration service', function() {

    var $compile,
        $rootScope,
        $httpBackend,
        ConfigurationService;

    beforeEach(module('BPACApp'));

    beforeEach(inject(function(_$compile_, _$rootScope_, _$httpBackend_, _ConfigurationService_){
        $compile = _$compile_;
        $rootScope = _$rootScope_.$new();
        $httpBackend = _$httpBackend_;

        jasmine.getJSONFixtures().fixturesPath = 'base/src/config';

        $httpBackend.whenGET(function(url) {
            return url.indexOf("config/app_conf.json") === 0;
        }).respond(
            getJSONFixture('app_conf.json')
        );

        ConfigurationService = _ConfigurationService_;

        ConfigurationService.loadConfiguration().then(function(data) {
            ConfigurationService.setConfiguration(data);
        });

        $httpBackend.flush();
        $rootScope.$digest();
    }));

    it('check number of returned page size options for the common grid and one value', function() {
        expect(ConfigurationService.getGridPageSizes().length).toEqual(3);
        expect(ConfigurationService.getGridPageSizes()[0].value).toEqual(10);
    });

    it('check policy types and one value', function() {
        expect(ConfigurationService.getPolicyTypes().length).toEqual(6);
        expect(ConfigurationService.getPolicyTypes()[0].value).toEqual("proAccelCategories");
        expect(ConfigurationService.getPolicyTypes()[0].i18nLabel).toEqual("createPolicy.optionsValues.proAccelCategories");
        expect(ConfigurationService.getPolicyTypes()[0].signatureSelect).toEqual("categories");
    });

    it('check deployment modes and one value', function() {
        expect(ConfigurationService.getPolicyDeploymentModes().length).toEqual(3);
        expect(ConfigurationService.getPolicyDeploymentModes()[1].value).toEqual("ids");
        expect(ConfigurationService.getPolicyDeploymentModes()[1].i18nLabel).toEqual("applyPolicyModal.deploymentIDS");
    });

    it('check policy actions and one value', function() {
        expect(ConfigurationService.getPolicyActions().length).toEqual(2);
        expect(ConfigurationService.getPolicyActions()[1].value).toEqual("block");
        expect(ConfigurationService.getPolicyActions()[1].i18nLabel).toEqual("applyPolicyModal.block");
    });

    it('check signature actions and one value', function() {
        expect(ConfigurationService.getSignatureActions().length).toEqual(8);
        expect(ConfigurationService.getSignatureActions()[7].value).toEqual("sdrop");
        expect(ConfigurationService.getSignatureActions()[7].i18nLabel).toEqual("createPolicy.AddNewSignatureValues.sdrop");
    });

    it('check signature help links', function() {
        expect(ConfigurationService.getSignatureHelpLinks().length).toEqual(2);
        expect(ConfigurationService.getSignatureHelpLinks()[0].flowControlLink).toEqual("https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Flow-keywords");
        expect(ConfigurationService.getSignatureHelpLinks()[1].contentLink).toEqual("https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Payload_keywords");
    });

    it('check flow control keywords and one value', function() {
        expect(ConfigurationService.getFlowControlKeywords().length).toEqual(4);
        expect(ConfigurationService.getFlowControlKeywords()[3].value).toEqual("stream_size");
        expect(ConfigurationService.getFlowControlKeywords()[3].format).toEqual("int");
    });

    it('check flow control keywords and one value', function() {
        expect(ConfigurationService.getContentKeywords().length).toEqual(13);
        expect(ConfigurationService.getContentKeywords()[12].value).toEqual("fast_pattern");
        expect(ConfigurationService.getContentKeywords()[12].format).toEqual("none");
    });

});
