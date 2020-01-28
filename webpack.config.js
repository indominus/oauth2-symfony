const Encore = require('@symfony/webpack-encore');

if (!Encore.isRuntimeEnvironmentConfigured()) {
    Encore.configureRuntimeEnvironment(process.env.NODE_ENV || 'dev');
}

let publicPath =  Encore.isDev() ? '/icard/pisp/unicredit/public/build' : '/oauth2/build';

Encore
    .setOutputPath('public/build/')
    .setPublicPath(publicPath)
    .setManifestKeyPrefix('build/')

    .addEntry('app', './assets/js/app.js')
    .addStyleEntry('common', './assets/scss/common.scss')

    .splitEntryChunks()
    .enableSingleRuntimeChunk()

    .enableSassLoader()

    .cleanupOutputBeforeBuild()

    .enableBuildNotifications(false)

    .enableVersioning(Encore.isProduction())
    .enableSourceMaps(!Encore.isProduction())
;

module.exports = Encore.getWebpackConfig();
