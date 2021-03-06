define(['angular','ops-mgr/jobs/module-name'], function (angular,moduleName) {

    var directive = function() {
        return {
            restrict: "EA",
            bindToController: {
                cardTitle: "@",
                pageName: '@'
            },
            controllerAs: 'vm',
            scope: true,
            templateUrl: 'js/ops-mgr/sla/service-level-assessments-template.html',
            controller: "ServiceLevelAssessmentsController",
            link: function($scope, element, attrs, controller) {

            }
        };
    }

    function controller($scope, $http,$timeout, $q, $mdToast, $mdPanel, OpsManagerJobService, TableOptionsService, PaginationDataService, StateService, IconService,
                                TabService,
                                AccessControlService, BroadcastService) {
        var self = this;

        /**
         * Indicates that admin operations are allowed.
         * @type {boolean}
         */
        self.allowAdmin = false;

        //Track active requests and be able to cancel them if needed
        this.activeRequests = [];

        this.pageName = angular.isDefined(this.pageName) ? this.pageName : 'service-level-assessments';
        //Page State
        this.loading = true;
        this.showProgress = true;

        //Pagination and view Type (list or table)
        this.paginationData = PaginationDataService.paginationData(this.pageName);
        PaginationDataService.setRowsPerPageOptions(this.pageName, ['5', '10', '20', '50', '100']);
        this.viewType = PaginationDataService.viewType(this.pageName);

        //Setup the Tabs
        var tabNames = ['All', 'Failed', 'Completed']
        this.tabs = TabService.registerTabs(this.pageName, tabNames, this.paginationData.activeTab);
        this.tabMetadata = TabService.metadata(this.pageName);

        this.sortOptions = loadSortOptions();

        /**
         * The filter supplied in the page
         * @type {string}
         */
        this.filter = '';

        //Load the data
        //   loadJobs();

        this.paginationId = function(tab) {
            return PaginationDataService.paginationId(self.pageName, tab.title);
        }
        this.currentPage = function(tab) {
            return PaginationDataService.currentPage(self.pageName, tab.title);
        }

        $scope.$watch(function() {
            return self.viewType;
        }, function(newVal) {
            self.onViewTypeChange(newVal);
        });


        $scope.$watch(function() {
            return self.filter;
        }, function (newVal, oldVal) {
            if (newVal != oldVal) {
                return loadAssessments(true).promise;
            }

        })

        this.onViewTypeChange = function(viewType) {
            PaginationDataService.viewType(this.pageName, self.viewType);
        }

        //Tab Functions

        this.onTabSelected = function(tab) {
            TabService.selectedTab(self.pageName, tab);
            return loadJobs(true).promise;
        };

        this.onOrderChange = function(order) {
            PaginationDataService.sort(self.pageName, order);
            TableOptionsService.setSortOption(self.pageName, order);
            return loadJobs(true).promise;
            //return self.deferred.promise;
        };

        this.onPaginationChange = function(page, limit) {
            var activeTab = TabService.getActiveTab(self.pageName);
            activeTab.currentPage = page;
            PaginationDataService.currentPage(self.pageName, activeTab.title, page);
            return loadJobs(true).promise;
        };

        /**
         * Build the possible Sorting Options
         * @returns {*[]}
         */
        function loadSortOptions() {
            var options = {'Name': 'name', 'Time':'time','Status': 'status'};

            var sortOptions = TableOptionsService.newSortOptions(self.pageName, options, 'time', 'desc');
            var currentOption = TableOptionsService.getCurrentSort(self.pageName);
            if (currentOption) {
                TableOptionsService.saveSortOption(self.pageName, currentOption)
            }
            return sortOptions;
        }



        /**
         * Called when a user Clicks on a table Option
         * @param option
         */
        this.selectedTableOption = function(option) {
            var sortString = TableOptionsService.toSortString(option);
            PaginationDataService.sort(self.pageName, sortString);
            var updatedOption = TableOptionsService.toggleSort(self.pageName, option);
            TableOptionsService.setSortOption(self.pageName, sortString);
            loadAssessments(true);
        }

        //Load Jobs

        function loadAssessments(force) {
            if (force || !self.refreshing) {

                if (force) {
                    angular.forEach(self.activeRequests, function(canceler, i) {
                        canceler.resolve();
                    });
                    self.activeRequests = [];
                }
                var activeTab = TabService.getActiveTab(self.pageName);

                self.refreshing = true;
                var sortOptions = '';
                var tabTitle = activeTab.title;
                var filters = {tabTitle: tabTitle};
                var limit = self.paginationData.rowsPerPage;

                var start = (limit * activeTab.currentPage) - limit; //self.query.page(self.selectedTab));

                var sort = PaginationDataService.sort(self.pageName);
                var canceler = $q.defer();
                var successFn = function(response) {
                    if (response.data) {

                        TabService.setTotal(self.pageName, tabTitle, response.data.recordsFiltered)

                        if (self.loading) {
                            self.loading = false;
                        }
                    }

                    finishedRequest(canceler);

                }
                var errorFn = function(err) {
                    finishedRequest(canceler);
                }
                var finallyFn = function() {

                }
                self.activeRequests.push(canceler);
                self.deferred = canceler;
                self.promise = self.deferred.promise;
                var filter = self.filter;

                var params = {start: start, limit: limit, sort: sort, filter:filter};


                $http.get(OpsManagerRestUrlService.LIST_SLA_ASSESSMENTS_URL, {timeout: canceler.promise, params: params}).then(successFn, errorFn);
            }
            self.showProgress = true;

            return self.deferred;

        }


        function finishedRequest(canceler) {
            var index = _.indexOf(self.activeRequests, canceler);
            if (index >= 0) {
                self.activeRequests.splice(index, 1);
            }
            canceler.resolve();
            canceler = null;
            self.refreshing = false;
            self.showProgress = false;
        }



        function clearRefreshTimeout(instanceId) {
            var timeoutInstance = self.timeoutMap[instanceId];
            if (timeoutInstance) {
                $timeout.cancel(timeoutInstance);
                delete self.timeoutMap[instanceId];
            }
        }


        this.assessmentDetails = function(event, assessment) {
           //TODO navigate to the assessment-details page
        }



        // Fetch allowed permissions
        AccessControlService.getUserAllowedActions()
            .then(function(actionSet) {
                self.allowAdmin = AccessControlService.hasAction(AccessControlService.OPERATIONS_ADMIN, actionSet.actions);
            });
    }


    angular.module(moduleName).controller("ServiceLevelAssessmentsController", ["$scope","$http","$timeout","$q","$mdToast","$mdPanel","OpsManagerJobService","TableOptionsService","PaginationDataService","StateService","IconService","TabService","AccessControlService","BroadcastService",controller]);
    angular.module(moduleName).directive('kyloServiceLevelAssessments', directive);
});

