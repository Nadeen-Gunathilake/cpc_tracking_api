const Joi = require('joi');

const locationSchema = Joi.object({
  empId: Joi.number().integer().required(),
  latitude: Joi.number().min(-90).max(90).required(),
  longitude: Joi.number().min(-180).max(180).required()
}).unknown(false);

module.exports = { locationSchema };
