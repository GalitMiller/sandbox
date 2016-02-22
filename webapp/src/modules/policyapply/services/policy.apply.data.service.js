angular.module("bricata.ui.policyapply")
    .factory("PolicyApplyDataService",
    ["$q", "CommonProxyForRequests", "PolicyApplication", "PolicyAppliedInfo", "SensorsDataService",
        function($q, CommonProxyForRequests, PolicyApplication, PolicyAppliedInfo, SensorsDataService){
            var service = {

                applyPolicy:function(applyData) {
                    return CommonProxyForRequests.getDecoratedPromise(
                        PolicyApplication.apply({}, applyData).$promise, true);
                },

                getAppliedPolicies:function(sensorId){
                    return CommonProxyForRequests.getDecoratedPromise(
                        PolicyAppliedInfo.query({
                            id: sensorId,
                            results_per_page: 10000
                        }).$promise);
                },

                loadAppliedPoliciesForSensors:function(sensorInterfaceRows, existingPolicies, existingPolicyActions,
                    percentage, progressObj){
                    var deferred = $q.defer();
                    var counters = {
                        pending: sensorInterfaceRows.length,
                        processed: 0
                    };

                    percentage = percentage / sensorInterfaceRows.length;

                    for (var i = 0; i < sensorInterfaceRows.length; i++) {
                        this.loadSensorApplicationInfo(sensorInterfaceRows[i], existingPolicies, existingPolicyActions,
                            counters, deferred, percentage, progressObj);
                    }

                    return deferred.promise;
                },

                loadSensorApplicationInfo: function(sensorInterfaceRow, existingPolicies, existingPolicyActions,
                                                    counters, topDefer, percentage, progressObj){
                    var _this = this;
                    this.getAppliedPolicies(sensorInterfaceRow.interface.id).then(function success(data) {
                        counters.processed++;

                        _this.validateAndSetLoadedPoliciesForInterface(sensorInterfaceRow,
                            data, existingPolicies, existingPolicyActions);

                        progressObj.progress += percentage;
                        if (counters.processed === counters.pending) {
                            topDefer.resolve();
                        }
                    });
                },

                validateAndSetLoadedPoliciesForInterface:function(sensorInterfaceRow, loadedPolicies,
                                                                  existingPolicies, existingPolicyActions){
                    sensorInterfaceRow.policies = [];
                    if (loadedPolicies && loadedPolicies.length > 0) {
                        var i;
                        var j;
                        var policyToAdd;
                        for (i = 0; i < loadedPolicies.length; i++) {
                            policyToAdd = null;
                            for (j = 0; j < existingPolicies.length; j++) {
                                if (loadedPolicies[i].policy_id === existingPolicies[j].id) {
                                    policyToAdd = existingPolicies[j];
                                    break;
                                }
                            }

                            if (policyToAdd) {
                                for (j = 0; j < existingPolicyActions.length; j++) {
                                    if (loadedPolicies[i].action === existingPolicyActions[j].value) {
                                        sensorInterfaceRow.policies.push({
                                            policy: policyToAdd,
                                            action: existingPolicyActions[j]
                                        });
                                        break;
                                    }
                                }
                            }
                        }
                    }
                },

                findIntersectionAndConflictsOfAppliedPolicies: function(sensorInterfaceRows){
                    var intersectionArr = sensorInterfaceRows[0].policies.concat([]);
                    var conflictingPolicies = [];
                    var intersectionObj = {};
                    var i, j;
                    var isFound;

                    for (i = 0; i < intersectionArr.length; i++) {
                        intersectionObj[intersectionArr[i].policy.id] = intersectionArr[i];
                    }

                    for (i = 1; i < sensorInterfaceRows.length; i++) {
                        for (var policyId in intersectionObj) {
                            isFound = false;
                            if (intersectionObj.hasOwnProperty(policyId)) {
                                for (j = 0; j < sensorInterfaceRows[i].policies.length; j++) {
                                    if (sensorInterfaceRows[i].policies[j].policy.id === parseInt(policyId)) {
                                        isFound = true;
                                        break;
                                    }
                                }

                                if (isFound) {
                                    if (sensorInterfaceRows[i].policies[j].action.value !==
                                        intersectionObj[policyId].action.value) {
                                        conflictingPolicies.push(sensorInterfaceRows[i].policies[j]);
                                        delete intersectionObj[policyId];
                                    }
                                } else {
                                    delete intersectionObj[policyId];
                                }
                            }
                        }
                    }

                    intersectionArr = [];

                    angular.forEach(intersectionObj, function (value) {
                        intersectionArr.push(value);
                    });

                    return {common: intersectionArr, conflicts: conflictingPolicies};
                },

                removeCommonPoliciesFromRows: function(sensorInterfaceRows, commonPolicies){
                    var commonPoliciesIndexes = {};
                    var i, j;

                    for (i = 0; i < commonPolicies.length; i++) {
                        commonPoliciesIndexes[commonPolicies[i].policy.id] = true;
                    }

                    for (i = 0; i < sensorInterfaceRows.length; i++) {
                        for (j = sensorInterfaceRows[i].policies.length - 1; j >= 0; j--) {
                            if (commonPoliciesIndexes[sensorInterfaceRows[i].policies[j].policy.id]) {
                                sensorInterfaceRows[i].policies.splice(j, 1);
                            }
                        }
                    }
                },

                mergeCommonPoliciesIntoRows: function(sensorInterfaceRows, commonPolicies){
                    var sensorInterfacePoliciesObj;

                    angular.forEach(sensorInterfaceRows, function (sensorInterfaceRow) {
                        sensorInterfacePoliciesObj = {};
                        angular.forEach(sensorInterfaceRow.policies, function (policyObj) {
                            sensorInterfacePoliciesObj[policyObj.policy.id] = policyObj;
                        });

                        angular.forEach(commonPolicies, function (commonPolicy) {
                            if (!sensorInterfacePoliciesObj[commonPolicy.policy.id] ||
                                sensorInterfacePoliciesObj[commonPolicy.policy.id].action.weight <
                                commonPolicy.action.weight){

                                sensorInterfacePoliciesObj[commonPolicy.policy.id] = commonPolicy;
                                sensorInterfacePoliciesObj[commonPolicy.policy.id].isCommon = true;
                            } else {
                                sensorInterfacePoliciesObj[commonPolicy.policy.id].isCommon = true;
                            }
                        });

                        sensorInterfaceRow.policies = [];
                        angular.forEach(sensorInterfacePoliciesObj, function (value) {
                            sensorInterfaceRow.policies.push(value);
                        });
                    });
                },

                extractNonCommonPolicies: function(sensorInterfaceRows){
                    var allNonCommon = [];
                    var nonCommon;

                    angular.forEach(sensorInterfaceRows, function (sensorInterfaceRow) {
                        nonCommon = [];

                        angular.forEach(sensorInterfaceRow.policies, function (policyObj) {
                            if (!policyObj.isCommon) {
                                nonCommon.push(policyObj);
                            }
                        });

                        if (nonCommon.length > 0) {
                            allNonCommon.push({
                                sensor: sensorInterfaceRow.sensor,
                                interface: sensorInterfaceRow.interface,
                                diff: nonCommon
                            });
                        }
                    });

                    return allNonCommon;
                },

                getNonConflictingPoliciesForSetUp: function(existingPolicies, conflictingPolicies) {
                    var i;
                    var existingPoliciesObj = {};
                    var nonConflictingPolicies = [];

                    for (i = 0; i < existingPolicies.length; i++) {
                        existingPoliciesObj[existingPolicies[i].id] = existingPolicies[i];
                    }

                    for (i = 0; i < conflictingPolicies.length; i++) {
                        if (existingPoliciesObj[conflictingPolicies[i].policy.id]) {
                            delete existingPoliciesObj[conflictingPolicies[i].policy.id];
                        }
                    }

                    angular.forEach(existingPoliciesObj, function (value) {
                        nonConflictingPolicies.push(value);
                    });

                    return nonConflictingPolicies;
                },

                excludeUncheckedDiffFromMerged: function(excludedObj, mergedRows){
                    var j;
                    for (var i = 0; i < mergedRows.length; i++) {
                        if (excludedObj[mergedRows[i].interface.id]) {
                            for (j = mergedRows[i].policies.length - 1; j >= 0; j--) {
                                if (excludedObj[mergedRows[i].interface.id][mergedRows[i].policies[j].policy.id]) {
                                    mergedRows[i].policies.splice(j, 1);
                                }
                            }
                        }
                    }
                },

                mergeManagedDifferences: function(managedDiff, mergedRows){
                    var j;
                    for (var i = 0; i < mergedRows.length; i++) {
                        if (managedDiff[mergedRows[i].interface.id]) {
                            for (j = 0; j < mergedRows[i].policies.length; j++) {
                                if (managedDiff[mergedRows[i].interface.id][mergedRows[i].policies[j].policy.id]) {
                                    mergedRows[i].policies[j] =
                                        managedDiff[mergedRows[i].interface.id][mergedRows[i].policies[j].policy.id];
                                }
                            }
                        }
                    }
                },

                setUpInterfacesForAllSensors: function(sensorInterfaceRows, allSensors, percentage, progressObj){
                    var deferred = $q.defer();
                    var counters = {
                        pending: allSensors.length,
                        processed: 0
                    };

                    percentage = percentage / allSensors.length;

                    for (var i = 0; i < allSensors.length; i++) {
                        this.setUpInterfacesForSensor(allSensors[i], sensorInterfaceRows, counters, deferred,
                            percentage, progressObj);
                    }

                    return deferred.promise;
                },

                setUpInterfacesForSensor: function(sensor, sensorInterfaceRows, counters, topDefer, percentage,
                                                   progressObj){
                    SensorsDataService.getSensorInterfaces(sensor.id).then(function success(data) {

                        counters.processed++;

                        var newSensor = angular.copy(sensor);
                        angular.forEach(data, function (interface) {
                            sensorInterfaceRows.push({
                                sensor: newSensor,
                                interface: interface,
                                policies: []
                            });
                        });

                        progressObj.progress += percentage;
                        if (counters.processed === counters.pending) {
                            topDefer.resolve();
                        }
                    }, function (error) {
                        topDefer.reject(error);
                    });
                }

            };
            return service;
        }]);