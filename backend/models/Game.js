const mongoose = require("mongoose"); 
 
const GameSchema = mongoose.Schema( 
  { 
    creator: { 
      name: { 
        type: String, 
        required: true, 
      }, 
      _user: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: "User", 
      }, 
      score: { 
        type: Number, 
        default: 0, 
      }, 
      answeredQuestions: { 
        type: Array, 
      }, 
    }, 
    otherPlayers: [ 
      { 
        name: { 
          type: String, 
        }, 
        _user: { 
          type: mongoose.Schema.Types.ObjectId, 
          ref: "User", 
        }, 
        score: { 
          type: Number, 
          default: 0, 
        }, 
        answeredQuestions: { 
          type: Array, 
        }, 
      }, 
    ], 
    finished: { 
      type: Boolean, 
      default: false, 
    }, 
    gameType: { 
      type: String, 
      enum: ["single_player", "multi_player"], 
      required: true, 
    }, 
  }, 
  { 
    timestamps: true, 
  } 
); 
 
module.exports = Game = mongoose.model("game", GameSchema); 
 