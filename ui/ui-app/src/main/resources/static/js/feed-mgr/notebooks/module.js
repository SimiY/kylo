define(['angular','feed-mgr/notebooks/module-name','kylo-utils/LazyLoadUtil','constants/AccessConstants','kylo-feedmgr','kylo-common','kylo-services'], function (angular,moduleName,lazyLoadUtil,AccessConstants) {
    //LAZY LOADED into the application
    var module = angular.module(moduleName, []);

    module.config(['$stateProvider','$compileProvider',function ($stateProvider,$compileProvider) {
        //preassign modules until directives are rewritten to use the $onInit method.
        //https://docs.angularjs.org/guide/migration#migrating-from-1-5-to-1-6
        $compileProvider.preAssignBindingsEnabled(true);

        $stateProvider.state(AccessConstants.UI_STATES.NOTEBOOKS.state,{
            url:'/notebooks',
            params: {},
            views: {
                'content': {
                    templateUrl: 'js/feed-mgr/notebooks/notebooks.html',
                    controller:'NotebooksController',
                    controllerAs:'vm'
                }
            },
            resolve: {
                loadMyCtrl: lazyLoadController(['feed-mgr/notebooks/NotebooksController'])
            },
            data: {
                breadcrumbRoot: false,
                displayName: 'Notebooks',
                module:moduleName,
                permissions:AccessConstants.UI_STATES.NOTEBOOKS.permissions
            }
        });




    }]);

    function lazyLoadController(path){
        return lazyLoadUtil.lazyLoadController(path,'feed-mgr/notebooks/module-require');
    }



});