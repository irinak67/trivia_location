import axios from "axios";
import React from "react";
import { API_URL, USER_STORAGE_KEY } from "../helpers/variables";

const useGame = () => {
  const user = JSON.parse(localStorage.getItem(USER_STORAGE_KEY));
  const createGame = async (name, gameType, _user) => {
    try {
      const response = await axios.post(`${API_URL}/game/creategame`, {
        creator_name: name,
        gameType,
        _user,
      });
      console.log(response.data);
      return response.data;
    } catch (err) {
      console.log(err.response?.data);
    }
  };

  const getGame = async _game => {
    try {
      const response = await axios.get(`${API_URL}/game/${_game}`);
      console.log(response);
      return response.data;
    } catch (err) {
      console.log(err.response);
    }
  };

  const answerQues = async (_game, answeredQuestion, remainingTime) => {
    try {
      const response = await axios.post(`${API_URL}/game/answer`, {
        _game,
        _user: user.userId,
        answeredQuestion,
        remainingTime,
      });

      console.log(response.data);
      return response.data;
    } catch (err) {
      alert(err.response?.data?.msg);
      return { answered: false };
    }
  };

  const finishGame = async _game => {
    try {
      const response = await axios.post(`${API_URL}/game/finishGame`, {
        _game,
      });
    } catch (err) {
      console.log(err);
    }
  };

  const joinGame = async (_game, name) => {
    try {
      const response = await axios.post(`${API_URL}/game/join`, {
        _user: user.userId,
        _game,
        name,
      });
      console.log(response);
      return response.data;
    } catch (err) {
      alert(err.response?.data?.msg);
    }
  };

  return { createGame, getGame, answerQues, finishGame, joinGame };
};

export default useGame;
