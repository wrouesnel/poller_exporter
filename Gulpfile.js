/**
 * Created by will on 6/09/15.
 */

var gulp = require('gulp');
var gulpif = require('gulp-if');
var run = require('gulp-run');

var minimist = require('minimist')

var knownOptions = {
    string: 'env',
    default: { env: process.env.NODE_ENV || 'dev' }
};

var options = minimist(process.argv.slice(2), knownOptions);

// Copy the bootstrap minified files and strip the min prefix for production.
gulp.task('copy bootstrap', function() {
    var infix = "";
    if (knownOptions.env == 'production') {
        infix = ".min";
    }

    gulp.src('./node_modules/bootstrap/dist/css/bootstrap'+infix+'.css')
        .pipe(gulp.dest('web/static/css'));

    gulp.src('./node_modules/bootstrap/dist/css/bootstrap-theme'+infix+'.css')
        .pipe(gulp.dest('web/static/css'));

    gulp.src('./node_modules/bootstrap/dist/js/bootstrap'+infix+'.js')
        .pipe(gulp.dest('web/static/js'));

    gulp.src('./node_modules/bootstrap/dist/fonts/*', {
        src: 'node_modules/bootstrap/dist'
    }).pipe(gulp.dest('web/static/fonts'));
});

gulp.task("build assetfs", ['copy bootstrap'], function () {
    if (knownOptions.env == 'production') {
        return run('go-bindata-assetfs -prefix=web web/...').exec();
    } else {
        return run('go-bindata-assetfs -debug -dev -prefix=web web/...').exec();
    }
});

gulp.task('default', ['copy bootstrap', 'build assetfs']);