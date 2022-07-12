import React from "react";
import Questions from "./Questions";
import io from "socket.io-client";
import { useEffect, useState } from "react";
import useGame from "../hooks/game.hook";
import { API_URL, USER_STORAGE_KEY } from "../helpers/variables";
const socket = io.connect(`${API_URL}`);

let highScores = 0;
function QuestionsRes() {
  const results = JSON.parse(localStorage.getItem("results"));
  const [newdata, setData] = useState([]);
  const [game, setGame] = useState();

  const [highestScore, setHighestScore] = useState(0);
  const [scoresObj, setScoresObj] = useState({
    myScore: 0,
    otherPlayerScore: 0,
  });
  const { getGame, finishGame } = useGame();

  useEffect(() => {
    // fetch("https://trivianodeserver.herokuapp.com/items")
    //   .then(res => res.json())
    //   .then(data => {
    //     console.log(data);
    //     setData(data);
    //   });

    getGameResults();
  }, []);

  useEffect(() => {
    const user = JSON.parse(localStorage.getItem(USER_STORAGE_KEY));
    socket.emit("connected", { user_id: user.userId });
    socket.on(`game_ended_${user.userId}`, ({ game }) => {
      setGame({
        ...game,
      });
    });
  }, [socket]);

  const getGameResults = async () => {
    const _game = JSON.parse(localStorage.getItem("game"))._game;
    console.log(_game, "----");
    const { game } = await getGame(_game);
    console.log(game, "---");

    // console.o
    // finishGame(game._id);

    setGame(game);
  };

  const gameStatus = game => {
    const user = JSON.parse(localStorage.getItem(USER_STORAGE_KEY));
    setScoresObj();
    highScores = game.creator.score;
    if (game.creator._user._id.toString() === user.userId) {
      setScoresObj({
        myScore: game.creator.score,
      });
    } else {
      game.otherPlayers.forEach(item => {
        console.log(item);

        if (user.userId === item._user._id)
          setScoresObj({
            myScore: item.score,
          });
      });

      console.log();
    }

    console.log(highScores);
    game.otherPlayers.forEach(item => {
      if (item.score > highScores) highScores = item.score;
    });

    setHighestScore(highScores);

    console.log(highScores);
  };

  useEffect(() => {
    console.log(highestScore);
  }, [highestScore]);

  useEffect(() => {
    if (game) gameStatus(game);
  }, [game]);

  return (
    <div className='resultsPage'>
      {console.log(scoresObj?.myScore, highScores)}
      <h1 style={{color: 'orange'}}>
        {scoresObj &&
          (scoresObj.myScore >= highestScore ? "You Win!" : "You Lose!")}
      </h1>
      <h2>Your Scores:{scoresObj && scoresObj.myScore}</h2>
      <h2></h2>
      <div className='resultsPage__results'>
        <div className='resultsPage__results__result'>
          <h3>{game?.creator.name}</h3>
          <h3>{game?.creator.score}</h3>
          {game?.creator.answeredQuestions.map((res, index) => {
            return (
              <>
                <div className='result-item'>
                  <h2 style={{height: '55%'}}>{res?.question}</h2>
                  <div className='result-answers'>
                    <div>
                      <h3>Your Answer:</h3>
                      <div>{res?.answer}</div>
                    </div>
                    <div>
                      {res?.answer === res?.correct_answer ? (
                        <h2 style={{color: '#68d868'}}>true</h2>
                      ) : (
                        <h2 style={{color: 'red'}}>false</h2>
                      )}
                    </div>
                    <div>
                      <h3>Correct Answer:</h3>
                      <div>{res?.correct_answer}</div>
                    </div>
                  </div>
                </div>
              </>
            );
          })}
        </div>
        {game?.gameType !== "single_player" &&
          game?.otherPlayers.map((item, key) => (
            <>
              <div className='resultsPage__results__result' key={key}>
                <h3>{item.name}</h3>
                <h3>{item.score}</h3>

                {item.answeredQuestions.map((res, index) => {
                  return (
                    <div className='result-item'>
                      <h2 style={{height: '55%'}}>{res?.question}</h2>
                      <div className='result-answers'>
                        <div>
                          <h3>Your Answer:</h3>
                          <div>{res?.answer}</div>
                        </div>
                        <div>
                          {res?.answer === res?.correct_answer ? (
                            <h2 style={{color: '#68d868'}}>true</h2>
                          ) : (
                            <h2 style={{color: 'red'}}>false</h2>
                          )}
                        </div>
                        <div>
                          <h3>Correct Answer:</h3>
                          <div>{res?.correct_answer}</div>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </>
          ))}
      </div>
    </div>
  );
}

export default QuestionsRes;
