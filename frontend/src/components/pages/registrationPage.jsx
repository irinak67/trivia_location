import React from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  Box,
  Typography,
  TextField,
  Container,
  Grid,
  CssBaseline,
} from "@mui/material";
import { useTranslation } from "react-i18next";
import Pop_reg from "../popup/pop_reg";
import { useState } from "react";
import { useHttp } from "../hooks/http.hook";
import GoogleLogin from "react-google-login";
import FacebookLogin from "react-facebook-login";
import axios from "axios";
import { API_URL, USER_STORAGE_KEY } from "../helpers/variables";

export default function Registration() {
  const navigate = useNavigate();
  const responseSuccessGoogle = response => {
    console.log(response);
    axios({
      method: "POST",
      url: `${API_URL}/api/auth/google`,
      // url: "/api/auth/google",
      data: { tokenId: response.tokenId },
    }).then(response => {
      console.log("Google login success", response);
      alert("Google login success");
      localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(response.data));

      setMainButtonActive(false);
    });
  };

  const responseErrorGoogle = response => {};

  const responseFacebook = response => {
    axios({
      method: "POST",
      url: `${API_URL}/api/auth/facebook`,
      data: { accessToken: response.accessToken, userID: response.userID },
    }).then(response => {
      console.log("Facebook login success, client side", response);
      alert("Facebook login success");
      setMainButtonActive(false);
    });
  };

  const { loading, error, request } = useHttp();

  const [form, setForm] = useState({
    email: "",
    password: "",
  });

  const changeHandler = event => {
    setForm({ ...form, [event.target.name]: event.target.value });
  };

  const [mainButtonActive, setMainButtonActive] = useState(true);
  // console.log(mainButtonActive)

  const loginHandler = async () => {
    try {
      const data = await axios.post(
        `${API_URL}/api/auth/login`,
        //"/api/auth/login",

        { ...form }
      );

      localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(data.data));

      console.log(data.data);
      // console.log(data);
      alert("Login is complete");

      setMainButtonActive(false);
      navigate("/Location");
      //navigate("/createGame");
      // console.log(mainButtonActive)
    } catch (e) {
      console.log(e.response);
      alert(e);
    }
  };

  const { t } = useTranslation();

  const [modalActive, setModalActive] = useState(false);

  return (
    <Container maxWidth='lg'>
      <Typography variant='h1' sx={{ fontWeight: "bold", mt: "1rem" }}>
        {t("Login with")}
      </Typography>
      <Grid container>
        <Grid
          item
          xs={12}
          md={6}
          sx={{
            mt: 3,
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
          }}
        >
          <CssBaseline />
          <TextField
            id='standard-basic'
            name='email'
            type='email'
            label={t("Email")}
            variant='outlined'
            margin='normal'
            fullWidth
            required
            onChange={changeHandler}
          />
          <TextField
            id='standard-basic'
            name='password'
            type='password'
            label={t("Password")}
            variant='outlined'
            className='reg_input'
            fullWidth
            required
            onChange={changeHandler}
          />

          <Link className='button' to='/Registration' onClick={loginHandler}>
            {t("Login")}
          </Link>
        </Grid>
        <Grid
          item
          xs={12}
          md={6}
          sx={{
            mt: 5,
            mb: { xs: 5 },
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
          }}
        >
          <Box component='div' sx={{ width: "90%" }}>
            {" "}
            {/*little bit smaller area*/}
            <FacebookLogin
              // className='socButton'
              appId='691605551987315'
              // autoLoad={true}
              fields='name,email,picture'
              cssClass='my-facebook-button-class'
              fullWidth
              required
              callback={responseFacebook}
            />
            <GoogleLogin
              className='socButton'
              clientId='602070662525-cg5up3456lcbdngu7nhji2j6inpi8t1b.apps.googleusercontent.com'
              buttonText='LOGIN WITH GOOGLE'
              onSuccess={responseSuccessGoogle}
              onFailure={responseErrorGoogle}
              cookiePolicy={"single_host_origin"}
            />
            <div className='button' onClick={() => setModalActive(true)} to='/'>
              {t("Registration")}
            </div>
          </Box>
        </Grid>
        <Box component='div' sx={{ width: "90%" }}>
          <Link to='/Location'>
            <button className='button' disabled={mainButtonActive}>
              {t("Choose location")}
            </button>
          </Link>
        </Box>

        <Pop_reg active={modalActive} setActive={setModalActive} />
      </Grid>
    </Container>
  );
}
