const path = require('path');
module.exports = {
    mode: 'development',
    entry: './src/keycloak.js',
    output: {
        filename: 'keycloak-code.js',
        path: path.resolve(__dirname, 'dist'),
        publicPath: '/dist/',
        library: 'keycloak-code',
        libraryTarget: 'umd',
        umdNamedDefine: true
    },
}