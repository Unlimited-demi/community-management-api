const express = require('express');


const connectDB = require('./config/db.js');
require('dotenv').config();


const swaggerSpec = require('./swagger.js');
const swaggerUI = require('swagger-ui-express');
const authRoutes = require('./routes/authRoutes');


const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

connectDB().then(() => {
  app.use('/api/auth', authRoutes);
  app.use('/api-docs', swaggerUI.serve, swaggerUI.setup(swaggerSpec));
  const port = process.env.PORT || 8080;
  app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
  });
}).catch((err) => {
  console.error('Error connecting to database:', err);
  process.exit(1);
});
