describe('bricata ui policy application', function() {

    var $compile,
        $controller,
        $rootScope,
        $httpBackend,
        PolicyApplyDataService,
        ConfigurationService;

    beforeEach(module('BPACApp'));

    beforeEach(inject(function(_$compile_, _$controller_, _$rootScope_, _$httpBackend_, _PolicyApplyDataService_,
                               _ConfigurationService_){
        $compile = _$compile_;
        $controller = _$controller_;
        $rootScope = _$rootScope_.$new();
        $httpBackend = _$httpBackend_;

        PolicyApplyDataService = _PolicyApplyDataService_;
        ConfigurationService = _ConfigurationService_;

        $rootScope.$digest();
    }));

    describe('PolicyApplyDataService methods check', function () {
        it('check intersection mechanism to match one', function() {
            var dataRows = [
                {
                    policies: [
                        {policy: {id: 1}, action: {value: 'alert'}},
                        {policy: {id: 2}, action: {value: 'alert'}},
                        {policy: {id: 3}, action: {value: 'alert'}}
                    ]
                },
                {
                    policies: [
                        {policy: {id: 4}, action: {value: 'alert'}},
                        {policy: {id: 2}, action: {value: 'alert'}},
                        {policy: {id: 5}, action:{value: 'alert'}}
                    ]
                },
                {
                    policies: [
                        {policy: {id: 7}, action:{value: 'alert'}},
                        {policy: {id: 6}, action:{value: 'alert'}},
                        {policy: {id: 2}, action:{value: 'alert'}}
                    ]
                }
            ];

            var intersection = PolicyApplyDataService.findIntersectionAndConflictsOfAppliedPolicies(dataRows).common;
            expect(intersection.length).toBe(1);
            expect(intersection[0].policy.id).toBe(2);
        });

        it('check intersection mechanism to match none', function() {
            var dataRows = [
                {
                    policies: [
                        {policy: {id: 1}, action:{value: 'alert'}},
                        {policy: {id: 2}, action:{value: 'alert'}},
                        {policy: {id: 3}, action:{value: 'alert'}}
                    ]
                },
                {
                    policies: [
                        {policy: {id: 4}, action:{value: 'alert'}},
                        {policy: {id: 5}, action:{value: 'alert'}},
                        {policy: {id: 6}, action:{value: 'alert'}}
                    ]
                },
                {
                    policies: [
                        {policy: {id: 7}, action:{value: 'alert'}},
                        {policy: {id: 8}, action:{value: 'alert'}},
                        {policy: {id: 9}, action:{value: 'alert'}}
                    ]
                }
            ];

            var intersection = PolicyApplyDataService.findIntersectionAndConflictsOfAppliedPolicies(dataRows).common;
            expect(intersection.length).toBe(0);
        });

        it('check intersection mechanism to match all', function() {
            var dataRows = [
                {
                    policies: [
                        {policy: {id: 1}, action:{value: 'alert'}},
                        {policy: {id: 2}, action:{value: 'alert'}},
                        {policy: {id: 3}, action:{value: 'alert'}}
                    ]
                },
                {
                    policies: [
                        {policy: {id: 3}, action:{value: 'alert'}},
                        {policy: {id: 2}, action:{value: 'alert'}},
                        {policy: {id: 1}, action:{value: 'alert'}}
                    ]
                },
                {
                    policies: [
                        {policy: {id: 2}, action:{value: 'alert'}},
                        {policy: {id: 3}, action:{value: 'alert'}},
                        {policy: {id: 1}, action:{value: 'alert'}}
                    ]
                }
            ];

            var intersection = PolicyApplyDataService.findIntersectionAndConflictsOfAppliedPolicies(dataRows).common;
            expect(intersection.length).toBe(3);
            expect(intersection[0].policy.id).toBe(1);
            expect(intersection[1].policy.id).toBe(2);
            expect(intersection[2].policy.id).toBe(3);
        });

        it('check intersection mechanism to match two', function() {
            var dataRows = [
                {
                    policies: [
                        {policy: {id: 1}, action:{value: 'alert'}},
                        {policy: {id: 2}, action:{value: 'alert'}},
                        {policy: {id: 3}, action:{value: 'alert'}}
                    ]
                },
                {
                    policies: [
                        {policy: {id: 3}, action:{value: 'alert'}},
                        {policy: {id: 2}, action:{value: 'alert'}},
                        {policy: {id: 5}, action:{value: 'alert'}}
                    ]
                },
                {
                    policies: [
                        {policy: {id: 2}, action:{value: 'alert'}},
                        {policy: {id: 3}, action:{value: 'alert'}},
                        {policy: {id: 1},action:{value: 'alert'}}
                    ]
                }
            ];

            var intersection = PolicyApplyDataService.findIntersectionAndConflictsOfAppliedPolicies(dataRows).common;
            expect(intersection.length).toBe(2);
            expect(intersection[0].policy.id).toBe(2);
            expect(intersection[1].policy.id).toBe(3);
        });

        it('check intersection mechanism to find conflicts', function() {
            var dataRows = [
                {
                    policies: [
                        {policy: {id: 1}, action:{value: 'alert'}},
                        {policy: {id: 2}, action:{value: 'alert'}},
                        {policy: {id: 3}, action:{value: 'alert'}}
                    ]
                },
                {
                    policies: [
                        {policy: {id: 3}, action:{value: 'alert'}},
                        {policy: {id: 2}, action:{value: 'block'}},
                        {policy: {id: 5}, action:{value: 'alert'}}
                    ]
                },
                {
                    policies: [
                        {policy: {id: 2}, action:{value: 'alert'}},
                        {policy: {id: 3}, action:{value: 'alert'}},
                        {policy: {id: 1},action:{value: 'alert'}}
                    ]
                }
            ];

            var intersection = PolicyApplyDataService.findIntersectionAndConflictsOfAppliedPolicies(dataRows);
            var common = intersection.common;
            var conflicts = intersection.conflicts;

            expect(common.length).toBe(1);
            expect(common[0].policy.id).toBe(3);

            expect(conflicts.length).toBe(1);
            expect(conflicts[0].policy.id).toBe(2);
        });

        it('check intersection mechanism to match all for single row', function() {
            var dataRows = [
                {
                    policies: [
                        {policy: { id: 1}, action:{value: 'alert'}},
                        {policy: {id: 2}, action:{value: 'alert'}},
                        {policy: {id: 3}, action:{value: 'alert'}}
                    ]
                }
            ];

            var intersection = PolicyApplyDataService.findIntersectionAndConflictsOfAppliedPolicies(dataRows).common;
            expect(intersection.length).toBe(3);
            expect(intersection[0].policy.id).toBe(1);
            expect(intersection[1].policy.id).toBe(2);
            expect(intersection[2].policy.id).toBe(3);
        });

        it('check intersection mechanism for finding common policies and removing them from each row', function() {
            var dataRows = [
                {
                    policies: [
                        {policy: {id: 1}, action:{value: 'alert'}},
                        {policy: {id: 2}, action:{value: 'alert'}},
                        {policy: {id: 3}, action:{value: 'alert'}}
                    ]
                },
                {
                    policies: [
                        {policy: {id: 3}, action:{value: 'alert'}},
                        {policy: {id: 2}, action:{value: 'alert'}},
                        {policy: {id: 5}, action:{value: 'alert'}}
                    ]
                },
                {
                    policies: [
                        {policy: {id: 1}, action:{value: 'alert'}},
                        {policy: {id: 2}, action:{value: 'alert'}},
                        {policy: {id: 6}, action:{value: 'alert'}},
                        {policy: {id: 3}, action:{value: 'alert'}}
                    ]
                }
            ];

            var intersection = PolicyApplyDataService.findIntersectionAndConflictsOfAppliedPolicies(dataRows).common;
            PolicyApplyDataService.removeCommonPoliciesFromRows(dataRows, intersection);

            expect(intersection.length).toBe(2);
            expect(intersection[0].policy.id).toBe(2);
            expect(intersection[1].policy.id).toBe(3);

            expect(dataRows[0].policies.length).toBe(1);
            expect(dataRows[0].policies[0].policy.id).toBe(1);

            expect(dataRows[1].policies.length).toBe(1);
            expect(dataRows[1].policies[0].policy.id).toBe(5);

            expect(dataRows[2].policies.length).toBe(2);
            expect(dataRows[2].policies[0].policy.id).toBe(1);
            expect(dataRows[2].policies[1].policy.id).toBe(6);
        });

        it('check merging mechanism for common policies and data rows', function() {
            var dataRows = [
                {
                    sensor: {id: 1},
                    interface: {id: 1},
                    policies: [
                        {policy: {id: 1}, action: {value: 'alert', weight: 0}},
                        {policy: {id: 2}, action: {value: 'block', weight: 1}}
                    ]
                },
                {
                    sensor: {id: 2},
                    interface: {id: 2},
                    policies: [
                        {policy: {id: 3}, action: {value: 'alert',weight: 0}}
                    ]
                },
                {
                    sensor: {id: 3},
                    interface: {id: 3},
                    policies: [
                        {policy: {id: 6},  action: {value: 'alert',weight: 0}}
                    ]
                }
            ];

            var common = [
                {
                    policy: {id: 2}, action: {value: 'alert',weight: 0}
                }
            ];
            PolicyApplyDataService.mergeCommonPoliciesIntoRows(dataRows, common);

            expect(dataRows[0].policies.length).toBe(2);
            expect(dataRows[0].policies[0].policy.id).toBe(1);
            expect(dataRows[0].policies[0].action.value).toBe('alert');
            expect(dataRows[0].policies[0].isCommon).toBe(undefined);
            expect(dataRows[0].policies[1].policy.id).toBe(2);
            expect(dataRows[0].policies[1].action.value).toBe('block');
            expect(dataRows[0].policies[1].isCommon).toBeTruthy();

            expect(dataRows[1].policies.length).toBe(2);
            expect(dataRows[1].policies[0].policy.id).toBe(3);
            expect(dataRows[1].policies[0].action.value).toBe('alert');
            expect(dataRows[1].policies[0].isCommon).toBe(undefined);
            expect(dataRows[1].policies[1].policy.id).toBe(2);
            expect(dataRows[1].policies[1].action.value).toBe('alert');
            expect(dataRows[1].policies[1].isCommon).toBeTruthy();

            expect(dataRows[2].policies.length).toBe(2);
            expect(dataRows[2].policies[0].policy.id).toBe(6);
            expect(dataRows[2].policies[0].action.value).toBe('alert');
            expect(dataRows[2].policies[0].isCommon).toBe(undefined);
            expect(dataRows[2].policies[1].policy.id).toBe(2);
            expect(dataRows[2].policies[1].action.value).toBe('alert');
            expect(dataRows[2].policies[1].isCommon).toBeTruthy();

            var nonCommon = PolicyApplyDataService.extractNonCommonPolicies(dataRows);
            expect(nonCommon.length).toBe(3);

            expect(nonCommon[0].sensor.id).toBe(1);
            expect(nonCommon[0].interface.id).toBe(1);
            expect(nonCommon[0].diff.length).toBe(1);
            expect(nonCommon[0].diff[0].policy.id).toBe(1);

            expect(nonCommon[1].sensor.id).toBe(2);
            expect(nonCommon[1].interface.id).toBe(2);
            expect(nonCommon[1].diff.length).toBe(1);
            expect(nonCommon[1].diff[0].policy.id).toBe(3);

            expect(nonCommon[2].sensor.id).toBe(3);
            expect(nonCommon[2].interface.id).toBe(3);
            expect(nonCommon[2].diff.length).toBe(1);
            expect(nonCommon[2].diff[0].policy.id).toBe(6);
        });

        it('check mechanism for validating previously applied policies against currently existing', function() {
            var sensorInterfaceRow = {};
            var loadedPolicies = [
                {policy_id: 1, action: 'block'},
                {policy_id: 2, action: 'fake'},
                {policy_id: 3, action: 'alert'}
            ];
            var existingPolicies = [
                {id: 1},
                {id: 2}
            ];
            var existingPolicyActions = [
                {value: 'alert'},
                {value: 'block'}
            ];

            PolicyApplyDataService.validateAndSetLoadedPoliciesForInterface(sensorInterfaceRow, loadedPolicies,
                existingPolicies, existingPolicyActions);

            expect(sensorInterfaceRow.policies.length).toBe(1);
            expect(sensorInterfaceRow.policies[0].policy.id).toBe(1);
            expect(sensorInterfaceRow.policies[0].action.value).toBe('block');
        });


        it('check mechanism for getting non conflicting policies', function() {
            var existingPolicies = [
                {id: 1},
                {id: 2}
            ];

            var conflicts = [
                {policy: {id: 1}}
            ];

            var nonConflicting = PolicyApplyDataService.getNonConflictingPoliciesForSetUp(existingPolicies, conflicts);
            expect(nonConflicting.length).toBe(1);
            expect(nonConflicting[0].id).toBe(2);
        });

        it('check mechanism for excluding unchecked differences', function() {
            var excludedPolicies = {
                1: {1: true},
                3: {6: true}
            };

            var dataRows = [
                {
                    sensor: {id: 1},
                    interface: {id: 1},
                    policies: [
                        {policy: {id: 1}, action: {value: 'alert', weight: 0}},
                        {policy: {id: 2}, action: {value: 'block', weight: 1}}
                    ]
                },
                {
                    sensor: {id: 2},
                    interface: {id: 2},
                    policies: [
                        {policy: {id: 3}, action: {value: 'alert',weight: 0}}
                    ]
                },
                {
                    sensor: {id: 3},
                    interface: {id: 3},
                    policies: [
                        {policy: {id: 6},  action: {value: 'alert',weight: 0}}
                    ]
                }
            ];

            PolicyApplyDataService.excludeUncheckedDiffFromMerged(excludedPolicies, dataRows);
            expect(dataRows.length).toBe(3);

            expect(dataRows[0].policies.length).toBe(1);
            expect(dataRows[0].policies[0].policy.id).toBe(2);

            expect(dataRows[1].policies.length).toBe(1);
            expect(dataRows[1].policies[0].policy.id).toBe(3);

            expect(dataRows[2].policies.length).toBe(0);
        });

        it('check mechanism for merging managed differences', function() {
            var finalDifferences = {
                1: {1: {policy: {id: 1}, action: {value: 'block', weight: 1}}},
                3: {6: {policy: {id: 6},  action: {value: 'block',weight: 1}}}
            };

            var dataRows = [
                {
                    sensor: {id: 1},
                    interface: {id: 1},
                    policies: [
                        {policy: {id: 1}, action: {value: 'alert', weight: 0}},
                        {policy: {id: 2}, action: {value: 'block', weight: 1}}
                    ]
                },
                {
                    sensor: {id: 2},
                    interface: {id: 2},
                    policies: [
                        {policy: {id: 3}, action: {value: 'alert',weight: 0}}
                    ]
                },
                {
                    sensor: {id: 3},
                    interface: {id: 3},
                    policies: [
                        {policy: {id: 6},  action: {value: 'alert',weight: 0}}
                    ]
                }
            ];

            PolicyApplyDataService.mergeManagedDifferences(finalDifferences, dataRows);
            expect(dataRows.length).toBe(3);

            expect(dataRows[0].policies.length).toBe(2);
            expect(dataRows[0].policies[0].policy.id).toBe(1);
            expect(dataRows[0].policies[0].action.value).toBe('block');
            expect(dataRows[0].policies[1].policy.id).toBe(2);
            expect(dataRows[0].policies[1].action.value).toBe('block');

            expect(dataRows[1].policies.length).toBe(1);
            expect(dataRows[1].policies[0].policy.id).toBe(3);
            expect(dataRows[1].policies[0].action.value).toBe('alert');

            expect(dataRows[2].policies.length).toBe(1);
            expect(dataRows[2].policies[0].policy.id).toBe(6);
            expect(dataRows[2].policies[0].action.value).toBe('block');
        });
    });

    describe('ApplyPolicyController methods check', function () {
        var $scope, controller;

        beforeEach(function () {
            jasmine.getJSONFixtures().fixturesPath = 'base/src';

            $httpBackend.whenGET(function(url) {
                return url.indexOf("config/app_conf.json") === 0;
            }).respond(
                getJSONFixture('config/app_conf.json')
            );

            $httpBackend.whenGET(function(url) {
                return url.indexOf('policies.json') > 0 || url.indexOf('policies/lite') > 0;
            }).respond(
                getJSONFixture('json-mocks/policies.json')
            );

            $httpBackend.whenGET(function(url) {
                return url.indexOf('sensorsControlled.json') > 0 || url.indexOf('sensors/controlled') > 0;
            }).respond(
                getJSONFixture('json-mocks/sensorsControlled.json')
            );

            $httpBackend.whenGET(function(url) {
                return url.indexOf('policy.applied_1') > 0 || url.indexOf('interfaces/1/applied_policies') > 0;
            }).respond(
                getJSONFixture('json-mocks/policy.applied_1.json')
            );

            $httpBackend.whenGET(function(url) {
                return url.indexOf('policy.applied_2') > 0 || url.indexOf('interfaces/2/applied_policies') > 0;
            }).respond(
                getJSONFixture('json-mocks/policy.applied_2.json')
            );

            $httpBackend.whenGET(function(url) {
                return url.indexOf('interfaces.json') > 0 || url.indexOf('interfaces/refresh') > 0;
            }).respond(
                getJSONFixture('json-mocks/interfaces.json')
            );

            ConfigurationService.loadConfiguration().then(function(data) {
                ConfigurationService.setConfiguration(data);
            });

            $scope = $rootScope;
            var fakeModal = {
                opened: {
                    then: function(){}
                },
                close: function(){}
            };

            $scope.setUpDifferences = function(){};

            controller = $controller('ApplyPolicyController', { $scope: $scope, $modalInstance: fakeModal });
            $controller('DifferenceManagementController', { $scope: $scope });
            $controller('PolicySelectionController', { $scope: $scope });
            $controller('SensorSelectionController', { $scope: $scope });
            $httpBackend.flush();
        });

        it('check controller initialization', function () {
            expect($scope.model.values.policies.length).toBeGreaterThan(0);
            expect($scope.model.values.sensors.length).toBe(2);
            expect($scope.model.values.sensors[0].id).toBe(1);
            expect($scope.model.values.sensors[1].id).toBe(2);

        });

        it('check controller navigation works', function () {
            //navigates to sensor selection
            $scope.goToSensorSelection();
            expect($scope.currentStep.first).toBeTruthy();
            expect($scope.currentStep.second).toBeFalsy();
            expect($scope.currentStep.third).toBeFalsy();

            //can't navigate to policy selection
            $scope.goToPolicySelection();
            expect($scope.currentStep.first).toBeTruthy();
            expect($scope.currentStep.second).toBeFalsy();
            expect($scope.currentStep.third).toBeFalsy();

            //navigates to policy selection
            $scope.states.refreshPoliciesNeeded = false;
            $scope.goToPolicySelection();
            expect($scope.currentStep.first).toBeFalsy();
            expect($scope.currentStep.second).toBeTruthy();
            expect($scope.currentStep.third).toBeFalsy();

            //navigates to differences management
            $scope.goToDiffManagement();
            expect($scope.currentStep.first).toBeFalsy();
            expect($scope.currentStep.second).toBeTruthy();
            expect($scope.currentStep.third).toBeFalsy();

            //can't navigate to differences management and remains on sensor selection
            $scope.goToSensorSelection();
            $scope.goToDiffManagement();
            expect($scope.currentStep.first).toBeTruthy();
            expect($scope.currentStep.second).toBeFalsy();
            expect($scope.currentStep.third).toBeFalsy();

            //can't navigate from policies to diff management
            $scope.goToPolicySelection();
            $scope.states.refreshPoliciesNeeded = true;
            $scope.goToDiffManagement();
            expect($scope.currentStep.first).toBeFalsy();
            expect($scope.currentStep.second).toBeTruthy();
            expect($scope.currentStep.third).toBeFalsy();

            //navigates to differences management
            $scope.states.refreshPoliciesNeeded = false;
            $scope.model.validation.policies = true;
            $scope.goToDiffManagement();
            expect($scope.currentStep.first).toBeFalsy();
            expect($scope.currentStep.second).toBeFalsy();
            expect($scope.currentStep.third).toBeTruthy();
        });

        it('check policy setup works with single interface', function () {
            $scope.model.validation.sensors = true;

            $scope.model.sensorInterfaces = [{interface: {id: 1}}];
            $scope.model.applyForAll = false;
            $scope.model.values.actions = ConfigurationService.getPolicyActions();

            $scope.goToPolicySelection();
            $httpBackend.flush();

            expect($scope.currentStep.first).toBeFalsy();
            expect($scope.currentStep.second).toBeTruthy();
            expect($scope.currentStep.third).toBeFalsy();

            expect($scope.model.commonPolicies.length).toBe(3);
            expect($scope.model.commonPolicies[0].policy.name).not.toBeUndefined();
            expect($scope.model.commonPolicies[1].policy.name).not.toBeUndefined();
            expect($scope.model.commonPolicies[2].policy.name).not.toBeUndefined();
            expect($scope.model.conflictingPolicies.length).toBe(0);
        });

        it('check policy setup works with all interfaces', function () {
            $scope.model.validation.sensors = true;
            $scope.model.applyForAll = true;
            $scope.model.sensorInterfaces = [];
            $scope.model.values.actions = ConfigurationService.getPolicyActions();

            $scope.goToPolicySelection();
            $httpBackend.flush();
            expect($scope.currentStep.first).toBeFalsy();
            expect($scope.currentStep.second).toBeTruthy();
            expect($scope.currentStep.third).toBeFalsy();

            expect($scope.model.commonPolicies.length).toBe(1);
            expect($scope.model.commonPolicies[0].policy.name).toBeUndefined();
            expect($scope.model.conflictingPolicies.length).toBe(2);
        });

        it('check policy differences setup works', function () {
            $scope.model.validation.sensors = true;
            $scope.model.applyForAll = true;
            $scope.model.sensorInterfaces = [];
            $scope.model.values.actions = ConfigurationService.getPolicyActions();

            $scope.goToPolicySelection();
            $httpBackend.flush();

            $scope.model.commonPolicies = [{policy: {id: 3}, action: {value: 'alert', weight: 0}}];

            $scope.states.refreshPoliciesNeeded = false;
            $scope.model.validation.policies = true;
            $scope.goToDiffManagement();

            expect($scope.model.differences.length).toBe(4);
            expect($scope.model.differences[0].diff.length).toBe(3);
            expect($scope.model.differences[1].diff.length).toBe(3);
            expect($scope.model.differences[2].diff.length).toBe(3);
            expect($scope.model.differences[3].diff.length).toBe(3);
        });

        it('check policy differences submit works', function () {
            $scope.model.validation.sensors = true;
            $scope.model.applyForAll = true;
            $scope.model.sensorInterfaces = [];
            $scope.model.values.actions = ConfigurationService.getPolicyActions();

            $scope.goToPolicySelection();
            $httpBackend.flush();

            $scope.model.commonPolicies = [{policy: {id: 3}, action: {value: 'alert', weight: 0}}];

            $scope.states.refreshPoliciesNeeded = false;
            $scope.model.validation.policies = true;
            $scope.goToDiffManagement();

            $httpBackend.expectPOST(function(url) {
                return url.indexOf('interfaces/apply_policies') > 0;
            }, function(dataStr) {
                return JSON.parse(dataStr).applications.length == 4;
            }).respond(
                {}
            );

            $scope.model.isValid = true;
            $scope.submitDifferences();
            $httpBackend.flush();
        });

        it('check policy selection', function () {
            expect($scope.model.commonPolicies.length).toBe(1);

            $scope.addPolicyRow();
            expect($scope.model.commonPolicies.length).toBe(2);

            $scope.removePolicyRow(0);
            expect($scope.model.commonPolicies.length).toBe(1);
        });

        it('check sensor selection', function () {
            expect($scope.model.sensorInterfaces.length).toBe(1);

            $scope.addSensorRow();
            expect($scope.model.sensorInterfaces.length).toBe(2);

            $scope.removeSensorRow(0);
            expect($scope.model.sensorInterfaces.length).toBe(1);
        });

        it('check sensor interfaces can be loaded', function () {
            var sensor = {id: 1};

            $scope.loadInterfacesForSensor(sensor);
            $httpBackend.flush();

            expect(sensor.interfaces.length).toBe(2);
        });

        it('check sensor selection type changes', function () {
            $scope.model.sensorInterfaces = [{interface: {id: 1}}];

            $scope.model.applyForAll = true;
            $scope.applyForOptionChange();
            expect($scope.model.sensorInterfaces.length).toBe(0);

            $scope.model.applyForAll = false;
            $scope.applyForOptionChange();
            expect($scope.model.sensorInterfaces.length).toBe(1);
            expect($scope.model.sensorInterfaces[0].interface.id).toBe(1);

            $scope.model.sensorInterfaces = [];
            $scope.model.applyForAll = true;
            $scope.applyForOptionChange();
            $scope.model.applyForAll = false;
            $scope.applyForOptionChange();
            expect($scope.model.sensorInterfaces.length).toBe(1);
            expect($scope.model.sensorInterfaces[0].sensor).not.toBeUndefined();
            expect($scope.model.sensorInterfaces[0].interface).not.toBeUndefined();
            expect($scope.model.sensorInterfaces[0].policies).not.toBeUndefined();
        });
    });
});
