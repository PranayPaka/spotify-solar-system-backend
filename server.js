const express = require("express");
const axios = require("axios");
const cors = require("cors");
const dotenv = require("dotenv");
const path = require("path");

// Load .env file
const env = dotenv.config({ path: path.resolve(__dirname, ".env") });
if (env.error) {
  console.error("Failed to load .env file:", env.error.message);
  process.exit(1);
}

const app = express();
app.use(cors({ origin: process.env.FRONTEND_URI || "http://localhost:5173" }));
app.use(express.json());

const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI =
  process.env.REDIRECT_URI || "http://127.0.0.1:5000/redirect";
const FRONTEND_URI = process.env.FRONTEND_URI || "http://localhost:5173";

if (!CLIENT_ID || !CLIENT_SECRET) {
  console.error(
    "Error: CLIENT_ID and CLIENT_SECRET must be defined in .env file"
  );
  process.exit(1);
}

app.get("/", (req, res) => {
  console.log("Root endpoint accessed");
  res.status(200).send("Spotify Solar System Backend is running!");
});

app.get("/login", (req, res) => {
  console.log("Initiating Spotify login");
  const scope = "user-top-read user-read-private";
  const authUrl = new URL("https://accounts.spotify.com/authorize");
  authUrl.searchParams.append("response_type", "code");
  authUrl.searchParams.append("client_id", CLIENT_ID);
  authUrl.searchParams.append("scope", scope);
  authUrl.searchParams.append("redirect_uri", REDIRECT_URI);
  res.redirect(authUrl.toString());
});

app.get("/redirect", async (req, res) => {
  const code = req.query.code;
  if (!code) {
    console.error("No authorization code provided in /redirect");
    return res.status(400).send("Error: No authorization code provided");
  }

  try {
    const tokenRes = await axios.post(
      "https://accounts.spotify.com/api/token",
      new URLSearchParams({
        code,
        redirect_uri: REDIRECT_URI,
        grant_type: "authorization_code",
      }).toString(),
      {
        headers: {
          Authorization: `Basic ${Buffer.from(
            `${CLIENT_ID}:${CLIENT_SECRET}`
          ).toString("base64")}`,
          "Content-Type": "application/x-www-form-urlencoded",
        },
      }
    );

    const { access_token, refresh_token } = tokenRes.data;
    console.log(
      "Access token obtained:",
      access_token.substring(0, 10) + "..."
    );
    console.log("Refresh token obtained:", refresh_token ? "Yes" : "No");
    // You can send both tokens to frontend if you want
    res.redirect(
      `${FRONTEND_URI}/?access_token=${access_token}&refresh_token=${refresh_token}`
    );
  } catch (error) {
    console.error(
      "Token exchange failed:",
      error.response?.data || error.message
    );
    res.status(error.response?.status || 500).send({
      error: "Error getting access token",
      details: error.response?.data?.error_description || error.message,
    });
  }
});

app.get("/me", async (req, res) => {
  const token = req.query.access_token;
  if (!token) return res.status(400).json({ error: "Missing access token" });

  try {
    const response = await axios.get("https://api.spotify.com/v1/me", {
      headers: { Authorization: `Bearer ${token}` },
    });
    res.json(response.data);
  } catch (error) {
    console.error("Token test failed", error.response?.data || error.message);
    res.status(403).json({ error: "Token test failed" });
  }
});

app.get("/top-tracks", async (req, res) => {
  const token = req.query.access_token?.trim();
  const timeRange = req.query.time_range || "short_term";

  if (!token) {
    console.error("No access token provided for /top-tracks");
    return res.status(400).json({ error: "Access token required" });
  }

  console.log(
    "Fetching top tracks with token:",
    token.substring(0, 10) + "..."
  );

  try {
    const response = await axios.get(
      `https://api.spotify.com/v1/me/top/tracks?limit=10&time_range=${timeRange}`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/json",
          "Content-Type": "application/json",
        },
      }
    );

    const topTracks = response.data.items;
    if (!topTracks.length) {
      console.warn("No top tracks found for user");
      return res
        .status(200)
        .json({ message: "No top tracks available", data: [] });
    }

    // Just send relevant track info — no audio features
    const data = topTracks.map((track, index) => ({
      rank: index + 1,
      name: track.name,
      artist: track.artists.map((a) => a.name).join(", "),
      albumImage: track.album.images[0]?.url || "",
      previewUrl: track.preview_url || "",
    }));

    res.json(data);
  } catch (err) {
    console.error("Failed to fetch top tracks:", {
      error: err.response?.data?.error || err.message,
      status: err.response?.status || "No status",
      requestUrl: err.config?.url || "Unknown",
    });

    res.status(err.response?.status || 400).json({
      error: "Failed to fetch top tracks",
      details: err.response?.data?.error?.message || err.message,
      status: err.response?.status || 400,
    });
  }
});

app.use((err, req, res, next) => {
  console.error("Server error:", err.stack);
  res
    .status(500)
    .json({ error: "Internal Server Error", details: err.message });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, "127.0.0.1", () => {
  console.log(`Server running on http://127.0.0.1:${PORT}`);
});
