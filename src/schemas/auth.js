const Joi = require('joi');

const loginSchema = Joi.object({
  EPF: Joi.string().required(),
  password: Joi.string().required()
}).unknown(false);

module.exports = { loginSchema };
