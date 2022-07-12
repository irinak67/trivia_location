const express = require("express"); 
const { default: mongoose } = require("mongoose"); 
const Game = require("../models/Game"); 
const User = require("../models/user.model"); 
const router = express.Router(); 
 
router.post("/creategame", async (req, res) => { 
  try { 
    const { creator_name, gameType, _user } = req.body; 
 
    console.log(req.body, "---------"); 
    const game = new Game({ 
      creator: { 
        name: creator_name, 
        _user, 
      }, 
      gameType, 
    }); 
    const response = await game.save(); 
 
    res.send({ game: response }); 
  } catch (err) { 
    res.status(500).send({ msg: err }); 
  } 
}); 
 
router.get("/:_game", async (req, res) => { 
  try { 
    const { _game } = req.params; 
 
    console.log(_game); 
 
    const game = await Game.findById(_game) 
      .populate({  
        model: "User", 
        path: "creator._user", 
      }) 
      .populate({ 
        model: "User", 
        path: "otherPlayers._user", 
      }); 
 
    if (!game) return res.status(404).send({ msg: "Game does not exist!" }); 
    res.send({ game }); 
  } catch (err) { 
    res.status(500).send({ msg: err }); 
  } 
}); 
 
router.post("/answer", async (req, res) => { 
  try { 
    let { _game, answeredQuestion, _user, remainingTime } = req.body;  
 
    console.log(answeredQuestion.question); 
 
    const game = await Game.findOne({ 
      _id: _game, 
    }); 
 
    if (game.creator._user.toString() === _user) { 
      let alreadyAnswered = game.creator.answeredQuestions.some( 
        q => q.question === answeredQuestion.question 
      ); 
      if (alreadyAnswered) 
        return res.status(400).send({ msg: "Already answered!" }); 
 
      game.creator.answeredQuestions.push(answeredQuestion); 
      if (answeredQuestion.answer == answeredQuestion.correct_answer) { 
        game.creator.score = game.creator.score + remainingTime; 
      } 
      await game.save(); 
    } else { 
      for (let i = 0; i < game.otherPlayers.length; i++) {  
        if (game.otherPlayers[i]._user.toString() === _user) {  
          let alreadyAnswered = game.otherPlayers[i].answeredQuestions.some( 
            q => q.question === answeredQuestion.question 
          ); 
          if (alreadyAnswered) 
            return res.status(400).send({ msg: "Already answered!" }); 
 
          game.otherPlayers[i].answeredQuestions.push(answeredQuestion); 
 
          console.log("I am other"); 
          if (answeredQuestion.answer == answeredQuestion.correct_answer) { 
            console.log(game.otherPlayers[i].score, "LLLLL"); 
            game.otherPlayers[i].score = 
              game.otherPlayers[i].score + remainingTime; 
          } 
          break; 
        } 
      } 
 
      await game.save(); 
    } 
 
    res.send({ answered: true }); 
  } catch (err) { 
    res.status(500).send({ msg: err }); 
  } 
}); 
 
router.post("/finishGame", async (req, res) => { 
  try { 
    const { _game } = req.body; 
 
    console.log(_game); 
    const response = await Game.findByIdAndUpdate( 
      _game, 
      { 
        finished: true, 
      }, 
      {  
        new: true, 
      } 
    ); 
 
    console.log(response); 
  
    res.send({ game: response }); 
  } catch (err) { 
    res.status(500).send({ msg: err }); 
  } 
}); 
 
router.post("/join", async (req, res) => { 
  try { 
    const { _game, _user, name } = req.body; 
 
    console.log(_user); 
    const user = await User.findById(_user); 
    if (!user) return res.status(401).send({ msg: "Please login!" }); 
 
    const game = await Game.findById(_game); 
    if (!game) return res.status(400).send({ msg: "Game not found!" }); 
 
    if (game.gameType === "single_player") { 
      if (game.creator._user.toString() === _user) 
        return res.status(400).send({ msg: "Cannot join this game!" }); 
      if (game.creator._user.toString() !== _user) 
        return res.status(400).send({ msg: "Access Denied!" }); 
    } 
 
    if (game.creator._user === user._id) return res.send({ isOwner: true }); 
 
    if (game.otherPlayers.length > 3) 
      return res.status(401).send({ msg: "Unable to join!" }); 
 
    const response = await Game.findByIdAndUpdate( 
      _game, 
      { 
        $addToSet: { 
          otherPlayers: { 
            name, 
            _user, 
          }, 
        }, 
      }, 
      { 
        new: true, 
      }  
    ) 
      .populate({ 
        model: "User", 
        path: "creator._user",  
      }) 
      .populate({ 
        model: "User", 
        path: "otherPlayers._user", 
      }); 
    if (!response) 
      return res.status(500).send({ msg: "Opps!Something went wrong!" }); 
 
    res.send({ game: response, isOwner: false }); 
  } catch (err) { 
    res.status(500).send({ msg: err }); 
  } 
}); 
 
module.exports = router; 
 