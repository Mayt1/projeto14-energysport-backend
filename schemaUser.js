import Joi from "joi";

const schemaUser = Joi.object({
    name: Joi.string().min(5).required(),
    email: Joi.string().email().min(5).max(50), 
    ///^[0-9]{3}\.[0-9]{3}\.[0-9]{3}\-[0-9]{2}$/
    password: Joi.string().pattern(new RegExp('^[a-zA-Z0-9]{3,30}$')),
    confirmPassword: Joi.ref('password')
});

export default schemaUser;