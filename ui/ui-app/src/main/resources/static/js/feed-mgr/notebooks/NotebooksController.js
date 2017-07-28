define(['angular','feed-mgr/notebooks/module-name'], function (angular,moduleName) {
    /**
     * Controller for the business metadata page.
     *
     * @constructor
     * @param $scope the application model
     * @param $http the HTTP service
     * @param {AccessControlService} AccessControlService the access control service
     * @param RestUrlService the Rest URL service
     */
    function NotebooksController($scope, $http, AccessControlService, RestUrlService) {
        var self = this;

        self.notebookurl = 'someurl';
    }

    // Register the controller
    angular.module(moduleName).controller('NotebooksController', ["$scope","$http","AccessControlService","RestUrlService",NotebooksController]);
});
