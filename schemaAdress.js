import Joi from "joi";

const schemaAdress = Joi.object({
    cep: Joi.string().required(),
    city: Joi.string().required(),
    state: Joi.string().required(),
    district: Joi.string().required(),
    road:Joi.string().required(),
    num:Joi.number().required(),
    complement:Joi.string(),
    value:Joi.number().required(),
});

export default schemaAdress;