const { Schema, model } = require("mongoose"); 
const schema = new Schema({ 
  name: { 
    type: String, 
    require: true, 
    minlength: 4, 
    maxlength: 50, 
  }, 
  age: { 
    type: Number, 
  }, 
  email: { 
    type: String, 
    require: true, 
    unique: true, 
  }, 
  password: { 
    type: String, 
    require: true, 
  }, 
  role: { 
    type: String, 
  }, 
  correctAnswers: { 
    default: 0, 
  }, 
  // links: [{ type: Types.ObjectId, ref: 'Link'}] 
}); 
 
module.exports = model("User", schema); 
 