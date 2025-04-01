<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>MikuMiku | Admin Dashboard</title>
  <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" crossorigin="anonymous" referrerpolicy="no-referrer" />
  <link rel="stylesheet" href="/styles.css">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <script src="/admin-dashboard.js"></script>
  <style>
    body {
      font-family: 'Roboto', sans-serif;
      background-color: #f5f5f5;
      color: #333;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      margin: 0;
    }
    .dashboard-container {
      background-color: #fff;
      padding: 40px;
      border-radius: 8px;
      box-shadow: 0 4px 6px rgba(0,0,0,0.1);
      width: 80%;
      max-width: 800px;
      margin: auto;
    }
    h2 {
      color: #007BFF;
      text-align: center;
      margin-bottom: 24px;
    }
    button {
      background-color: #007BFF;
      color: #fff;
      border: none;
      padding: 10px 20px;
      border-radius: 4px;
      cursor: pointer;
      margin-left: 10px;
    }
    button:hover {
      background-color: #0056b3;
    }
    .real-time-info, .user-list, .toggle-section {
      margin-top: 20px;
    }
    .ip-list {
      margin: 0;
      padding: 0;
      list-style: none;
      max-height: 200px;
      overflow-y: auto;
      border: 1px solid #e9e9e9;
      border-radius: 4px;
    }
    .ip-item {
      background-color: #e9e9e9;
      padding: 10px;
      margin: 5px 0;
      border-radius: 4px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .chart-container {
      margin-top: 40px;
      text-align: center;
    }
    canvas {
      margin: 0 auto;
      display: block;
    }
    .toggle-section {
      text-align: center;
    }
    .toggle-section label {
      font-size: 1em;
      margin-right: 8px;
    }
  </style>
</head>
<body>
  <div class="dashboard-container">
    <h2>Admin Dashboard</h2>
    <button id="logout">Logout</button>
    <div class="toggle-section">
      <label for="lfgToggle">LFG Command Enabled:</label>
      <input type="checkbox" id="lfgToggle">
    </div>
    <div class="real-time-info">
      <h3>Real-time Active Users</h3>
      <p id="active-users-count">Loading active user count...</p>
    </div>
    <div class="user-list">
      <h3>Active Users</h3>
      <ul id="active-ip-list" class="ip-list">Loading...</ul>
    </div>
    <div class="chart-container">
      <h3>Visitors by Country</h3>
      <canvas id="locationChart" width="400" height="200"></canvas>
    </div>
  </div>
</body>
</html>
