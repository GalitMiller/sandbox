angular.module('bricata.ui.signature')
    .factory("SignatureWizardService", [
        'ConfigurationService', 'SignatureDataService', 'CommonModalService', '$q',
        function (ConfigurationService, SignatureDataService, CommonModalService, $q) {
            var prepareDataBeforeSending = function(data) {
                if (data.references.length === 1 && data.references[0].typeId === null) {
                    data.references = [];
                }
            };

            var restoreDataAfterSending = function(data) {
                if (data.references.length === 0) {
                    data.references = [{typeId: null, value: ''}];
                }
            };

            var setEditDataForRulesInfo = function(model, data){
                model.action = data.action;
                model.protocolId = data.protocol.id;
                model.unidirectional = !data.is_bidirectional;
                if (data.src_host === null) {
                    model.source.ip.anyIp = true;
                } else {
                    model.source.ip.ip = data.src_host;
                }
                if (data.src_port === null) {
                    model.source.port.anyPort = true;
                } else {
                    model.source.port.port = data.src_port;
                }
                if (data.dst_host === null) {
                    model.destination.ip.anyIp = true;
                } else {
                    model.destination.ip.ip = data.dst_host;
                }
                if (data.dst_port === null) {
                    model.destination.port.anyPort = true;
                } else {
                    model.destination.port.port = data.dst_port;
                }
            };

            var setEditDataForSignatureInfo = function(model, data){
                model.name = data.name;
                model.categoryId = data.category.id;
                model.message = data.message;
                model.flowControlTxt = data.flow_control;
                model.contentTxt = data.content_control;
            };

            var setEditDataForMetaInfo = function(model, data, isCloning){
                if (data.class_type) {
                    model.classTypeID = data.class_type.id;
                }
                model.revision = data.revision;
                if (data.references && data.references.length > 0) {
                    model.references = [];
                    for(var i = 0; i < data.references.length; i++) {
                        model.references.push({
                            typeId: data.references[i].reference_type_id,
                            value: data.references[i].value
                        });
                    }
                }
                if (!isCloning) {
                    model.sid = data.sid;
                }

                model.gid = data.gid;
                model.severityId = data.severity.id;
            };

            return {
                initializeModel: function(selectedCategoryId, completeHandler) {

                    var signatureModel = {};

                    signatureModel.data = {
                        action: null,
                        protocolId: null,
                        source: {
                            ip: {ip: '', anyIp: false},
                            port: {port: '', anyPort: false}
                        },
                        unidirectional: true,
                        destination: {
                            ip: {ip: '', anyIp: false},
                            port: {port: '', anyPort: false}
                        },
                        name: '',
                        categoryId: (selectedCategoryId ? selectedCategoryId : null),
                        message: '',
                        flowControlTxt: '',
                        contentTxt: '',
                        classTypeID: null,
                        revision: 1,
                        references: [{typeId: null, value: ''}],
                        sid: '',
                        gid: '',
                        severityId: null
                    };

                    signatureModel.values = {
                        actionList: ConfigurationService.getSignatureActions(),
                        protocolList: [],
                        classTypeList: [],
                        referenceTypes: [],
                        severities: []
                    };

                    // The checkbox in the final step in the modal
                    signatureModel.previewSignaturesBeforeSavingCheckBox = {
                        checked : false
                    };

                    signatureModel.validation = {
                        first: {
                            isActionValid: false,
                            isProtocolValid: false,
                            isSourceValid: false,
                            isDestinationValid: false
                        },
                        second: {
                            isNameValid: false,
                            isCategoryValid: false,
                            isMessageValid: false
                        },
                        third: {
                            isClassTypeValid: false,
                            isReferenceValid: true,
                            noDuplicatedReferenceFound: true,
                            isRevisionValid: false,
                            isSIDValid: false,
                            isGIDValid: false
                        }
                    };

                    this.loadValuesData(signatureModel, completeHandler);

                    return signatureModel;
                },

                loadValuesData: function(dataModel, completeHandler) {
                    $q.all([
                        SignatureDataService.getClassTypes(),
                        SignatureDataService.getReferenceTypes(),
                        SignatureDataService.getSeverities(),
                        SignatureDataService.getProtocols(),
                        SignatureDataService.getSignatureSID(),
                        SignatureDataService.getSignatureCategoriesLite()
                    ]).then(function(data) {
                        dataModel.values.classTypeList = data[0];
                        dataModel.values.referenceTypes = data[1];
                        dataModel.values.severities = data[2];
                        dataModel.values.protocolList = data[3];
                        dataModel.data.sid = data[4].sid;
                        dataModel.data.gid = 1;
                        dataModel.categories = data[5];

                        if (completeHandler) {
                            completeHandler();
                        }
                    });
                },

                convertEditDataToModel: function(data, model, isCloning) {
                    if (!isCloning) {
                        model.id = data.id;
                    }

                    setEditDataForRulesInfo(model, data);
                    setEditDataForSignatureInfo(model, data);
                    setEditDataForMetaInfo(model, data, isCloning);
                },

                previewSignature: function(signatureData, cancelActionMethod, submitActionMethod, previewLoadFail) {
                    prepareDataBeforeSending(signatureData);

                    SignatureDataService.sendDataForPreview(signatureData).then(function(previewData) {
                            CommonModalService.show({
                                templateUrl: 'modules/signature/views/modals/preview-rule-modal.html',
                                backdrop: cancelActionMethod ? false : true,
                                controller: 'SignaturePreviewController',
                                resolve: {
                                    cancelCallback: function() {
                                        return function() {
                                            restoreDataAfterSending(signatureData);
                                            if (cancelActionMethod) {
                                                cancelActionMethod();
                                            }
                                        };
                                    },
                                    submitCallback: function() {
                                        return submitActionMethod;
                                    },
                                    ruleString: function() {
                                        return previewData;
                                    }
                                }
                            });

                        }, function(reason) {
                            restoreDataAfterSending(signatureData);
                            previewLoadFail(reason);
                        });
                },

                saveSignature: function(data, successCallBack, errorCallback) {
                    prepareDataBeforeSending(data);

                    SignatureDataService.createSignature(data).then(function(response) {
                        successCallBack(response);
                    }, function(reason) {
                        restoreDataAfterSending(data);
                        errorCallback(reason);
                    });
                },

                editSignature: function(data, successCallBack, errorCallback) {
                    prepareDataBeforeSending(data);

                    SignatureDataService.editSignature(data).then(function(response) {
                        successCallBack(response);
                    }, function(reason) {
                        restoreDataAfterSending(data);
                        errorCallback(reason);
                    });
                },

                processValidationResults: function(validationModel, eventData) {
                    if (angular.isDefined(eventData) && angular.isDefined(eventData.name) &&
                        eventData.name.indexOf('_') > 0) {
                        var validationProperty = eventData.name.split('_');

                        if (angular.isDefined(validationModel[validationProperty[0]]) &&
                            angular.isDefined(validationModel[validationProperty[0]][validationProperty[1]])) {
                            validationModel[validationProperty[0]][validationProperty[1]] = eventData.isValid;
                        }
                    }
                },

                isStepValid: function(validationStepModel) {
                    var isValid = true;
                    for (var key in validationStepModel) {
                        if (validationStepModel[key] === false) {
                            isValid = false;
                            break;
                        }
                    }

                    return isValid;
                },

                openNewSignatureCategoryDialog: function(cancelHandler, submitHandler, categories) {
                    CommonModalService.show({
                        templateUrl: 'modules/signature/views/modals/new-signature-category-modal.html',
                        windowClass: 'new-signature-category-modal-window',
                        controller: 'SignatureNewCategoryController',
                        resolve: {
                            cancelCallback: function(){
                                return function() {
                                    if (cancelHandler) {
                                        cancelHandler();
                                    }
                                };
                            },
                            submitCallback: function(){
                                return submitHandler;
                            },
                            existingCategories: function(){
                                return categories;
                            }
                        }
                    });
                },

                openNewSignatureSeverityDialog: function(cancelHandler, submitHandler, severities) {
                    CommonModalService.show({
                        templateUrl: 'modules/signature/views/modals/new-signature-severity-modal.html',
                        windowClass: 'new-signature-category-modal-window',
                        controller: 'SignatureNewSeverityController',
                        resolve: {
                            cancelCallback: function(){
                                return function() {
                                    if (cancelHandler) {
                                        cancelHandler();
                                    }
                                };
                            },
                            submitCallback: function(){
                                return submitHandler;
                            },
                            existingSeverities: function(){
                                return severities;
                            }
                        }
                    });
                },

                syncSeverityWithClassTypeSelection: function(data, values) {
                    if (data.classTypeID !== null) {

                        var i;
                        var selectedPriority;
                        for (i = 0; i < values.classTypeList.length; i++) {
                            if (values.classTypeList[i].id === data.classTypeID) {
                                selectedPriority = values.classTypeList[i].priority;
                                break;
                            }
                        }

                        var ranges = ConfigurationService.getSeverityRanges();
                        for (i = 0; i < ranges.length; i++) {
                            if (ranges[i].priority === selectedPriority ||
                                (i === (ranges.length - 1) && ranges[i].priority <= selectedPriority)){
                                data.severityId = ranges[i].priority;
                                break;
                            }
                        }
                    }
                }
            };

        }]);