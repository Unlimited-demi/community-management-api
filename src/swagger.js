const swaggerJSDoc = require('swagger-jsdoc');
const version = require('../package.json').version;
const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Community Management Tool API',
      version : "1.0.0"
    },
  },
  apis: [`${__dirname}/routes/*.js`]
};

const swaggerSpec = swaggerJSDoc(options);
module.exports = swaggerSpec;