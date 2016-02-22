angular.module('bricata.ui.signature')
    .factory("SignatureSelectionService", [
        function () {
            return {
                sortById: function(collection) {
                    collection.sort(function (a, b) {
                        if (a.id > b.id) {
                            return 1;
                        }
                        if (a.id < b.id) {
                            return -1;
                        }
                        return 0;
                    });
                },

                extractSelectedIds: function(selectionStorage){
                    var selectedIds = [];

                    if (Object.keys(selectionStorage).length > 0) {
                        angular.forEach(selectionStorage, function(isSelected, entityId) {
                            if (isSelected) {
                                selectedIds.push(entityId);
                            }
                        });
                    }

                    return selectedIds;
                },

                processCategorySelectionChange: function(selectedCategoryIDs, signatureCategories, recipientModel){
                    recipientModel.splice(0, recipientModel.length);

                    var i;
                    var signatureLength;
                    angular.forEach(selectedCategoryIDs, function(isSelected, categoryId) {
                        if (isSelected) {
                            var categoryIdNumber = parseInt(categoryId);
                            var category;
                            for (var j = 0; j < signatureCategories.length; j++) {
                                category = signatureCategories[j];

                                if (category.id === categoryIdNumber && category.signatures &&
                                    category.signatures.length > 0) {

                                    signatureLength = category.signatures.length;
                                    i = -1;
                                    while (++i < signatureLength) {
                                        recipientModel.push(category.signatures[i]);
                                    }

                                    break;
                                }
                            }
                        }
                    });
                },

                processSignatureSelectionChange: function(selectedSignatureIDs, availableSignatures, selectionModel){
                    var indexedSelectionModel = {};
                    var indexedAvailableSignatures = {};
                    var i;
                    for (i = 0; i < selectionModel.length; ++i) {
                        indexedSelectionModel[selectionModel[i].id] = selectionModel[i];
                    }

                    for (i = 0; i < availableSignatures.length; i++) {
                        indexedAvailableSignatures[availableSignatures[i].id] = availableSignatures[i];
                    }

                    angular.forEach(selectedSignatureIDs, function (isSelected, signatureId) {
                        if (isSelected) {
                            if (!indexedSelectionModel[signatureId]) {
                                indexedSelectionModel[signatureId] = indexedAvailableSignatures[signatureId];
                            }
                        } else {
                            if (indexedSelectionModel[signatureId]) {
                                delete indexedSelectionModel[signatureId];
                            }
                        }
                    });
                    selectionModel.splice(0, selectionModel.length);

                    angular.forEach(indexedSelectionModel, function (value) {
                        selectionModel.push(value);
                    });
                }
            };
        }]);