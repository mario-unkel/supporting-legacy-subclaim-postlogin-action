/**
* Handler that will be called during the execution of a PostLogin flow.
*
* @param {Event} event - Details about the user and the context in which they are logging in.
* @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
*/
exports.onExecutePostLogin = async (event, api) => {
 // initiate management API. Check cache for token first.
 const {domain} = event.secrets || {};
 const management = await getCachedManagementClient(event, api);


 // Search for existing users in uuidv4-db
 const {data: users} = await management.usersByEmail.getByEmail({email: event?.user?.email});
 console.log(users);


 console.log(users.some(record => record.identities.some(identity => identity.connection === 'uuidv4-db')));
 if (users.some(record => record.identities.some(identity => identity.connection === 'uuidv4-db'))) {
   return;
 } else {
   console.log('No users found. Create uuidv4 identity...');
 }


 // Import the v4 function from the uuid package
 const { v4: uuidv4 } = require('uuid');
 // Generate a UUIDv4
 const newUuid = uuidv4();
 // Log the generated UUID
 console.log('Generated UUIDv4:', newUuid);


 async function getCachedManagementClient(event, api) {
   const {ManagementClient, AuthenticationClient} = require('auth0');


   const domain = event?.secrets?.domain || event.request?.hostname; // we need domain for happy path. see return


   let {value: token} = api.cache.get('management-token') || {};


   if (!token) {
       console.log('cache MIS m2m token');


       const {clientId, clientSecret} = event.secrets || {};
       if (!clientId || !clientSecret) throw new Error('missing clientId or clientSecret in secrets');




       const cc = new AuthenticationClient({domain, clientId, clientSecret});
       const {data} = await cc.oauth.clientCredentialsGrant({audience: `https://${domain}/api/v2/`});
       token = data?.access_token;


       if (!token) throw new Error('failed get api v2 cc token');
         const result = api.cache.set('management-token-first',token.slice(0,2048), {ttl: data.expires_in * 10000})
         api.cache.set('management-token-second', token.slice(2048,4096), {ttl: data.expires_in * 10000})
         api.cache.set('management-token-third', token.slice(4096), {ttl: data.expires_in * 10000})


        if (result?.type === 'error') console.log(`WARNING: failed to set the token in the cache with error code: ${result.code}`);
   } else {
       console.log('cache HIT m2m token');
   }


   return new ManagementClient({domain, token});
 }


 function generateRandomPassword(length) {
   const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:",.<>/?';
   let result = '';
   const randomValues = new Uint32Array(length);
   crypto.getRandomValues(randomValues);


   for (let i = 0; i < length; i++) {
     result += characters[randomValues[i] % characters.length];
   }


   // Ensure the password has at least one special character
   const hasSpecialChar = /[!@#$%^&*()_+\-=[\]{}|;:'",.<>/?]/.test(result);
   if (!hasSpecialChar) {
     const specialChars = '!@#$%^&*()_+-=[]{}|;:",.<>/?';
     const randomIndex = Math.floor(Math.random() * length);
     const randomSpecialChar = specialChars[Math.floor(Math.random() * specialChars.length)];
     result = result.slice(0, randomIndex) + randomSpecialChar + result.slice(randomIndex + 1);
   }


   return result;
 }


 const minLength = 15;
 const randomValue = generateRandomPassword(minLength);
 console.log(randomValue);


 //create UUIDv4 identity
 const newUuidIdentity = {
   "email": event.user.email,
   "given_name": event.user.given_name,
   "family_name": event.user.family_name,
   "name": event.user.name,
   "nickname": event.user.nickname,
   "connection": "uuidv4-db",
   "user_id": newUuid,
   "email_verified": true,
   "password": randomValue
 }


 //create the new uuidv4 identity
 try {
       await management.users.create(newUuidIdentity);
       api.user.setUserMetadata("uuidv4", newUuid);
   } catch (err) {
       console.log('unable to create user, try again '+err);
       return;
 }


 const linkBody = {
   "provider": event.connection.strategy,
   "user_id": event.user.user_id
 }


 const linkReqParam = {
   "id": "auth0|"+newUuid,
 }
  //link identity
 try {
   await management.users.link(linkReqParam, linkBody)
   api.authentication.setPrimaryUser('auth0|'+newUuid);
 } catch (err) {
   console.log('unable to link identities, try again '+err);
   return;
 }


};


/**
* Handler that will be invoked when this action is resuming after an external redirect. If your
* onExecutePostLogin function does not perform a redirect, this function can be safely ignored.
*
* @param {Event} event - Details about the user and the context in which they are logging in.
* @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
*/
// exports.onContinuePostLogin = async (event, api) => {
// };
