// Expo config plugin entry point. Expo resolves `app.plugin.js` at the package
// root when a consumer lists this package in their app config `plugins` array.
// It re-exports the compiled plugin, which enables TLS hostname verification in
// the react-native-tcp-socket Android native transport during prebuild.
module.exports = require('./dist/cjs/plugin/index.js').default;
