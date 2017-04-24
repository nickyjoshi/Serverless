'use strict';

var AWS = require('aws-sdk');
var crypto = require('crypto');
var jwt = require('jsonwebtoken');
var dynamo = new AWS.DynamoDB.DocumentClient();

module.exports.register = (event, context, callback) => {

  var body = JSON.parse(event.body);

  console.log("body.username: " + body.username);

  if(!body.username || !body.password){
    const response = {
      statusCode: 500,
      body: JSON.stringify("Empty Username or Password"),
    };
  callback(null, response);
  return;
  }

  //create hash and salt of password
  var salt = crypto.randomBytes(16).toString('hex');
  var hash = crypto.pbkdf2Sync(body.password, salt, 1000, 64).toString('hex');

const params = {
    TableName: process.env.DYNAMODB_TABLE,
    Item: {
      username: body.username,
      salt: salt,
      hash: hash
    },
  };

  dynamo.put(params, (error, result) => {
    // handle potential errors
    if (error) {
      console.error(error);
      callback(new Error('Couldn\'t write to users.'));
      return;
    }
  
  //Generate JWT to return back JSONWebToken to client
  var jwt = generateJWT(body.username);

  console.log(JSON.stringify(jwt));

  const response = {
      statusCode: 200,
      body: JSON.stringify(jwt),
    };
    callback(null, response);
  });
};

module.exports.login = (event, context, callback) => {
    var body = JSON.parse(event.body);

    console.log("body.username: " + body.username);

    if(!body.username || !body.password){
          const response = {
          statusCode: 500,
          body: JSON.stringify("Empty Username or Password"),
    };
    callback(null, response);
    return;
  }

const params = {
    TableName: process.env.DYNAMODB_TABLE,
    Key: {
      username: body.username
    },
  };

  dynamo.get(params, (error, result) => {
    // handle potential errors

    var responseString = "Invalid user";

    console.log(JSON.stringify(result));

    if (Object.getOwnPropertyNames(result).length  != 0){

      var storedUsername = result.Item.username;
      var storedHash = result.Item.hash;
      var storedSalt = result.Item.salt;

      //create hash of input password
      var hash = crypto.pbkdf2Sync(body.password, storedSalt, 1000, 64).toString('hex');

      if (body.username == storedUsername && hash == storedHash){
        responseString = generateJWT(storedUsername);
      }else{
        responseString = "Invalid user";
      }

      if (error) {
        console.error(error);
        callback(new Error('Couldn\'t write to users.'));
        return;
      }
    }

  const response = {
      statusCode: 200,
      body: JSON.stringify(responseString),
    };
    callback(null, response);
  });
}

module.exports.getName = (event, context, callback) => {

    const response = {
          statusCode: 200,
          body: JSON.stringify("AntonyGonzales"),
        };
        callback(null, response);
}

module.exports.authorizerFunc = (event, context, callback) => {
    var token = event.authorizationToken;

    //var token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Impvc2hpdGtkIiwiZXhwIjoxNDkzMDcwNzI0LCJpYXQiOjE0OTI2Mzg3MjR9.M_7SeC0s5r9A0tvIh5tqXYJbjcsSAaT65PHl20y_sLk';
    var result = '';
    console.log("token:" + token);
    console.log("event.methodArn: " + event.methodArn);
    try{
        var decoded = jwt.verify(token, 'SECRET');
    }catch(e){
        decoded == null;
    }
    if (decoded == null){
      result = 'deny';
    }else{
      result = 'allow';
      //look at the object here and look at expiry time
      console.log(JSON.stringify(decoded));
      var tokenExpiry = decoded.exp;

      //Get the current UNIX Timestamp

     var ts = Math.round((new Date()).getTime() / 1000);
     console.log("value of UNIX timestamp is: " + ts);
      
      var today = new Date();
      console.log("Current timestamp is: "+ today.valueOf);
      console.log(tokenExpiry);

      if (tokenExpiry < ts){
        //token is expired - return a deny
        result = 'deny';
      }
    }
  console.log("Value of decoded: " + decoded);

    // Call oauth provider, crack jwt token, etc.
    // In this example, the token is treated as the status for simplicity.

    switch (result) {
        case 'allow':
            callback(null, generatePolicy('user', 'Allow', event.methodArn));
            break;
        case 'deny':
            callback(null, generatePolicy('user', 'Deny', event.methodArn));
            break;
        case 'unauthorized':
            callback("Unauthorized");   // Return a 401 Unauthorized response
            break;
        default:
            callback("Error: Invalid token"); 
    }
}


function generateJWT(username){
   
    var today = new Date();
    var exp = new Date(today);
    //set expiry date 5 days from today
    exp.setDate(today.getDate()+ 7);

    return jwt.sign({
        username:username,
        exp:parseInt(exp.getTime()/1000), },'SECRET');
}

function validateJWT(token){

  var decoded = jwt.verify(token, 'SECRET');
  console.log("Value of decoded: " + decoded) // bar

}

var generatePolicy = function(principalId, effect, resource) {
    var authResponse = {};
    
    authResponse.principalId = principalId;
    if (effect && resource) {
        var policyDocument = {};
        policyDocument.Version = '2012-10-17'; // default version
        policyDocument.Statement = [];
        var statementOne = {};
        statementOne.Action = 'execute-api:Invoke'; // default action
        statementOne.Effect = effect;
        statementOne.Resource = resource;
        policyDocument.Statement[0] = statementOne;
        authResponse.policyDocument = policyDocument;
    }
    
    // Can optionally return a context object of your choosing.
    /*authResponse.context = {};
    authResponse.context.stringKey = "stringval";
    authResponse.context.numberKey = 123;
    authResponse.context.booleanKey = true;*/
    return authResponse;
}
