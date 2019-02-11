const path = require('path');

const webpack = require('webpack');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const ExtractTextPlugin = require('extract-text-webpack-plugin');
const CopyWebpackPlugin = require("copy-webpack-plugin");

module.exports = {
//    devtool: 'eval-source-map',
//    devServer: {
//        hot: true,
//        hotOnly: true,
//        publicPath: '/',
//        stats: {
//            colors: true,
//        }
//    },
    entry: {
        main: ['./web/main.js']
    },
    output: {
        path: path.resolve('./assets/generated/static/'),
        filename: '[name].js',
        publicPath: '/static'
    },
    resolve: {
        modules: [
            path.resolve('./web'),
            path.resolve('./node_modules')
        ]
    },
    plugins: [
        new ExtractTextPlugin('[name].css'),
        new webpack.HotModuleReplacementPlugin()
    ],
    module: {
        loaders: [{
            test: /\.js?$/,
            exclude: /node_modules/,
            loader: 'babel-loader',
            query: {
                compact: false,
                presets: ["react", "es2015", "es2016", "es2017", "react-hmre"],
                plugins: [
                    ["transform-decorators-legacy"]
                ]
            }
        }, {
            test: /\.json?$/,
            loader: 'json'
        }, {
            test: /\.styl$/,
            loader: 'style-loader!css-loader!stylus-loader'
        }, {
            test: /\.css$/,
            loader: ExtractTextPlugin.extract({
                fallback: "style-loader",
                use: "css-loader"
            })
        }, {
            test: /\.(woff|woff2)(\?v=\d+\.\d+\.\d+)?$/,
            loader: 'url-loader?name=[name]-[hash].[ext]&limit=10000&mimetype=application/font-woff'
        }, {
            test: /\.ttf(\?v=\d+\.\d+\.\d+)?$/,
            loader: 'url-loader?name=[name]-[hash].[ext]&limit=10000&mimetype=application/octet-stream'
        }, {
            test: /\.eot(\?v=\d+\.\d+\.\d+)?$/,
            loader: 'file-loader?name=[name]-[hash].[ext]'
        }, {
            test: /\.svg(\?v=\d+\.\d+\.\d+)?$/,
            loader: 'url-loader?name=[name]-[hash].[ext]&limit=10000&mimetype=image/svg+xml'
        }]
    }
};
