import axios from "axios";

const baseURL = import.meta.env.PROD ? import.meta.env.VITE_API_URL : "http://localhost:9000/api";

const API = axios.create({
  baseURL,
  withCredentials: true,
});

// Authentication is handled via HttpOnly cookies (withCredentials: true),
// so we no longer need to manually attach an auth-token header.

export default API;
