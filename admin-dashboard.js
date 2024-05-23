<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard</title>
    <link rel="stylesheet" href="public/styles.css">
</head>
<body>
    <div class="admin-container">
        <h2>Admin Dashboard</h2>
        <button id="logout">Logout</button>
        <h3>Add Video</h3>
        <form id="video-form">
            <label for="video-title">Title</label>
            <input type="text" id="video-title" name="title" required>
            <label for="video-url">URL</label>
            <input type="text" id="video-url" name="url" required>
            <label for="video-description">Description</label>
            <textarea id="video-description" name="description" required></textarea>
            <button type="submit">Add Video</button>
        </form>
    </div>
    <script src="public/admin-dashboard.js"></script>
</body>
</html>

document.getElementById('video-form').addEventListener('submit', function(event) {
    event.preventDefault();

    const title = document.getElementById('video-title').value;
    const url = document.getElementById('video-url').value;
    const description = document.getElementById('video-description').value;

    const video = { title, url, description };

    console.log('New video added:', video);

    document.getElementById('video-form').reset();
});

document.getElementById('logout').addEventListener('click', function() {
    window.location.href = 'admin-login.html';
});
