document.getElementById('video-form').addEventListener('submit', function(event) {
    event.preventDefault();

    const title = document.getElementById('video-title').value;
    const url = document.getElementById('video-url').value;
    const description = document.getElementById('video-description').value;

    const video = { title, url: url.replace('youtu.be', 'youtube.com/embed'), description };

    // Save to local storage (for demo purposes; use a server/database in production)
    let videos = JSON.parse(localStorage.getItem('videos')) || [];
    videos.push(video);
    localStorage.setItem('videos', JSON.stringify(videos));

    // Clear the form
    document.getElementById('video-form').reset();
});

document.getElementById('logout').addEventListener('click', function() {
    window.location.href = 'admin-login.html';
});
