'use strict';
/**
 * Gruntfile.js is used to configure or define tasks and load Grunt plugins.
 *
 * Use uglify with Grunt to minify all ".js" file in documentation
 * Use yuidoc to generate the docs
 *
 * @class Gruntfile
 * @module Grunt file
 * @date 21/04/2015
 * @author ROBERT Mathieu <mathieu@yocto.re>
 * @copyright Yocto SAS, All Right Reserved <http://www.yocto.re>
 *
 */
 module.exports = function(grunt) {
   // init config
   grunt.initConfig({
     // default package
     pkg : grunt.file.readJSON('package.json'),

     /**
      * Jshint permit to flags suspicious usage in programs
      * @submodule jshint
      */
     jshint : {
       options : {
           node : true,
           yui : true,
       },
       all : [ 'src/index.js' ]
     },

     /**
      * Yuidoc permit to generate the yuidoc of the Yocto Stack Generator
      *
      * @submodule yuidoc
      */
     yuidoc : {
       compile : {
         name        : '<%= pkg.name %>',
         description : '<%= pkg.description %>',
         version     : '<%= pkg.version %>',
         url         : '<%= pkg.homepage %>',
         options     : {
           paths   : '.',
           outdir  : 'documentation',
           exclude : 'Gruntfile.js,example,dist,documentation,node_modules'
         }
       },
     },

    /**
     * Uglify permit to minify javascript file
     *
     * @submodule uglify
     */
     uglify : {
       api : {
          src    : 'src/index.js',
          dest   : 'dist/index.js'
       }
     }
   });

   // Load the plugins
   grunt.loadNpmTasks('grunt-contrib-jshint');
   grunt.loadNpmTasks('grunt-contrib-uglify');
   grunt.loadNpmTasks('grunt-contrib-yuidoc');
   grunt.loadNpmTasks('grunt-mocha-cli');

   // register tasks
   grunt.registerTask('default', [ 'jshint', 'mochacli','yuidoc', 'uglify' ]);
   grunt.registerTask('norme', 'jshint');
   grunt.registerTask('tests', 'mochacli');
   grunt.registerTask('build', [ 'jshint', 'yuidoc', 'uglify' ]);
 };
