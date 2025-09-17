const Joi = require('joi');

const createEmployeeSchema = Joi.object({
  firstName: Joi.string().min(2).max(100).required(),
  lastName: Joi.string().min(2).max(100).required(),
  EPF: Joi.string().min(3).max(10).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  adminRights: Joi.boolean()
}).unknown(false);

const updateEmployeeSchema = Joi.object({
  firstName: Joi.string().min(2).max(100).required(),
  lastName: Joi.string().min(2).max(100).required(),
  EPF: Joi.string().min(3).max(10).required(),
  email: Joi.string().email().required(),
  adminRights: Joi.boolean().required()
}).unknown(false);

module.exports = { createEmployeeSchema, updateEmployeeSchema };
