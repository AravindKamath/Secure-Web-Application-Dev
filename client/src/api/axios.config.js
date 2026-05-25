import axios from "axios";

//change 5000 to 9000 later
//made 5000 to run locally

const baseURL = import.meta.env.PROD ? import.meta.env.VITE_API_URL : "http://localhost:5000/api";

const API = axios.create({
  baseURL,
  withCredentials: true,
});

// Authentication is handled via HttpOnly cookies (withCredentials: true),
// so we no longer need to manually attach an auth-token header.

export default API;
