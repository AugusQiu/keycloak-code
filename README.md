# keycloak-code
keycloak-js modification, only used to get code
````js
// example of use
import Keycloak from 'keycloak-code';
const keycloak = new Keycloak('keycloak.json');
keycloak.init({ onLoad: 'login-required' }).success((code) => {
   console.log(code)
});
````