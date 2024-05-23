document.getElementById('video-form').addEventListener('submit', function(event) {
    event.preventDefault();

    const title = document.getElementById('video-title').value;
    const url = document.getElementById('video-url').value;
    const description = document.getElementById('video-description').value;

    const video = { title, url: url.replace('youtu.be', 'youtube.com/embed'), description };

    const token = localStorage.getItem('token');

    fetch('/api/videos', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'x-access-token': token
        },
        body: JSON.stringify(video)
    })
    .then(response => {
        if (response.ok) {
            alert('Video added successfully');
            document.getElementById('video-form').reset();
        } else {
            alert('Failed to add video');
        }
    })
    .catch(error => {
        console.error('Error:', error);
    });
});

document.getElementById('logout').addEventListener('click', function() {
    localStorage.removeItem('token');
    window.location.href = 'admin-login.html';
});
