const express = require("express");
const axios = require("axios");
const cors = require("cors");
const dotenv = require("dotenv");
const path = require("path");

// Load .env file
const env = dotenv.config({ path: path.resolve(__dirname, ".env") });
if (env.error) {
  console.error("Failed to load .env file:", env.error.message);
  // Don't exit in production - environment variables might be set directly
  if (process.env.NODE_ENV !== 'production') {
    process.exit(1);
  }
}

const app = express();

// Updated CORS configuration for Vercel frontend
app.use(cors({ 
  origin: [
    "https://spotify-frontend-orcin.vercel.app",
    "http://localhost:5173",
    "http://localhost:3000"
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI || "https://spotify-solar-system-backend.onrender.com/redirect";
const FRONTEND_URI = process.env.FRONTEND_URI || "https://spotify-frontend-orcin.vercel.app";

if (!CLIENT_ID || !CLIENT_SECRET) {
  console.error(
    "Error: CLIENT_ID and CLIENT_SECRET must be defined in environment variables"
  );
  if (process.env.NODE_ENV !== 'production') {
    process.exit(1);
  }
}

// Health check endpoint
app.get("/health", (req, res) => {
  res.status(200).json({ 
    status: "OK", 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

app.get("/", (req, res) => {
  console.log("Root endpoint accessed");
  res.status(200).json({ 
    message: "Spotify Solar System Backend is running!",
    status: "active",
    endpoints: ["/login", "/redirect", "/me", "/top-tracks", "/health", "/recent-tracks"]
  });
});

app.get("/login", (req, res) => {
  console.log("Initiating Spotify login");
  
  if (!CLIENT_ID) {
    return res.status(500).json({ error: "Spotify CLIENT_ID not configured" });
  }
  
  const scope = "user-top-read user-read-private user-read-recently-played";
  const authUrl = new URL("https://accounts.spotify.com/authorize");
  authUrl.searchParams.append("response_type", "code");
  authUrl.searchParams.append("client_id", CLIENT_ID);
  authUrl.searchParams.append("scope", scope);
  authUrl.searchParams.append("redirect_uri", REDIRECT_URI);
  
  console.log("Redirecting to:", authUrl.toString());
  res.redirect(authUrl.toString());
});

app.get("/redirect", async (req, res) => {
  const code = req.query.code;
  const error = req.query.error;
  
  if (error) {
    console.error("Spotify authorization error:", error);
    return res.redirect(`${FRONTEND_URI}/?error=${encodeURIComponent(error)}`);
  }
  
  if (!code) {
    console.error("No authorization code provided in /redirect");
    return res.redirect(`${FRONTEND_URI}/?error=${encodeURIComponent("No authorization code provided")}`);
  }

  try {
    console.log("Exchanging code for token...");
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
    console.log("Access token obtained:", access_token ? access_token.substring(0, 10) + "..." : "None");
    console.log("Refresh token obtained:", refresh_token ? "Yes" : "No");
    
    // Redirect to frontend with tokens
    const redirectUrl = `${FRONTEND_URI}/?access_token=${encodeURIComponent(access_token)}${refresh_token ? `&refresh_token=${encodeURIComponent(refresh_token)}` : ''}`;
    res.redirect(redirectUrl);
    
  } catch (error) {
    console.error("Token exchange failed:", error.response?.data || error.message);
    const errorMessage = error.response?.data?.error_description || error.message || "Token exchange failed";
    res.redirect(`${FRONTEND_URI}/?error=${encodeURIComponent(errorMessage)}`);
  }
});

app.get("/me", async (req, res) => {
  const token = req.query.access_token || req.headers.authorization?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(400).json({ error: "Missing access token" });
  }

  try {
    const response = await axios.get("https://api.spotify.com/v1/me", {
      headers: { 
        Authorization: `Bearer ${token}`,
        Accept: "application/json"
      },
    });
    res.json(response.data);
  } catch (error) {
    console.error("User profile fetch failed:", error.response?.data || error.message);
    res.status(error.response?.status || 403).json({ 
      error: "Failed to fetch user profile",
      details: error.response?.data?.error?.message || error.message
    });
  }
});

app.get("/top-tracks", async (req, res) => {
  const token = req.query.access_token?.trim() || req.headers.authorization?.replace('Bearer ', '');
  const timeRange = req.query.time_range || "short_term";
  const limit = req.query.limit || "10";

  if (!token) {
    console.error("No access token provided for /top-tracks");
    return res.status(400).json({ error: "Access token required" });
  }

  console.log("Fetching top tracks with token:", token.substring(0, 10) + "...");
  console.log("Time range:", timeRange, "Limit:", limit);

  try {
    const response = await axios.get(
      `https://api.spotify.com/v1/me/top/tracks`,
      {
        params: {
          limit: parseInt(limit),
          time_range: timeRange
        },
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/json",
          "Content-Type": "application/json",
        },
      }
    );

    // ADD DETAILED LOGGING HERE
    console.log("=== SPOTIFY API RESPONSE DEBUG ===");
    console.log("Response Status:", response.status);
    console.log("Full Response Data:", JSON.stringify(response.data, null, 2));
    console.log("Items Array:", response.data.items);
    console.log("Items Length:", response.data.items ? response.data.items.length : 'No items property');
    console.log("Total Available:", response.data.total);
    console.log("=====================================");

    const topTracks = response.data.items;
    if (!topTracks || !topTracks.length) {
      console.warn("No top tracks found for user");
      console.log("Response data keys:", Object.keys(response.data));
      console.log("Total from API:", response.data.total);
      
      return res.status(200).json({ 
        message: "No top tracks available", 
        data: [],
        total: 0,
        debug_info: {
          api_total: response.data.total,
          time_range: timeRange,
          response_keys: Object.keys(response.data)
        }
      });
    }

    // Send relevant track info
    const data = topTracks.map((track, index) => ({
      rank: index + 1,
      id: track.id,
      name: track.name,
      artist: track.artists.map((a) => a.name).join(", "),
      artists: track.artists,
      album: track.album.name,
      albumImage: track.album.images[0]?.url || "",
      previewUrl: track.preview_url || "",
      spotifyUrl: track.external_urls.spotify,
      popularity: track.popularity,
      duration_ms: track.duration_ms
    }));

    console.log("Successfully processed", data.length, "tracks");

    res.json({
      tracks: data,
      total: data.length,
      time_range: timeRange
    });
    
  } catch (err) {
    console.error("=== SPOTIFY API ERROR DEBUG ===");
    console.error("Error Status:", err.response?.status);
    console.error("Error Data:", JSON.stringify(err.response?.data, null, 2));
    console.error("Request URL:", err.config?.url);
    console.error("Full Error:", err.message);
    console.error("================================");

    res.status(err.response?.status || 400).json({
      error: "Failed to fetch top tracks",
      details: err.response?.data?.error?.message || err.message,
      status: err.response?.status || 400,
      debug_info: {
        spotify_error: err.response?.data,
        request_url: err.config?.url
      }
    });
  }
});

// Add recent tracks endpoint for testing
app.get("/recent-tracks", async (req, res) => {
  const token = req.query.access_token?.trim() || req.headers.authorization?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(400).json({ error: "Access token required" });
  }

  console.log("Fetching recent tracks with token:", token.substring(0, 10) + "...");

  try {
    const response = await axios.get(
      `https://api.spotify.com/v1/me/player/recently-played?limit=10`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/json"
        }
      }
    );

    console.log("=== RECENT TRACKS RESPONSE ===");
    console.log("Recent tracks response:", JSON.stringify(response.data, null, 2));
    console.log("===============================");
    
    res.json(response.data);
  } catch (err) {
    console.error("Recent tracks error:", err.response?.data);
    res.status(err.response?.status || 400).json({
      error: "Failed to fetch recent tracks",
      details: err.response?.data
    });
  }
});

// Refresh token endpoint
app.post("/refresh-token", async (req, res) => {
  const { refresh_token } = req.body;
  
  if (!refresh_token) {
    return res.status(400).json({ error: "Refresh token required" });
  }

  try {
    const response = await axios.post(
      "https://accounts.spotify.com/api/token",
      new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refresh_token,
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

    res.json(response.data);
  } catch (error) {
    console.error("Token refresh failed:", error.response?.data || error.message);
    res.status(error.response?.status || 400).json({
      error: "Failed to refresh token",
      details: error.response?.data?.error_description || error.message,
    });
  }
});

// Global error handler
app.use((err, req, res, next) => {
  console.error("Server error:", err.stack);
  res.status(500).json({ 
    error: "Internal Server Error", 
    details: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ 
    error: "Endpoint not found",
    available_endpoints: ["/", "/login", "/redirect", "/me", "/top-tracks", "/recent-tracks", "/health"]
  });
});

const PORT = process.env.PORT || 5000;

// Fixed: Changed from 127.0.0.1 to 0.0.0.0 for Render compatibility
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📱 Frontend URI: ${FRONTEND_URI}`);
  console.log(`🔄 Redirect URI: ${REDIRECT_URI}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🎵 Render URL: https://spotify-solar-system-backend.onrender.com`);
});
