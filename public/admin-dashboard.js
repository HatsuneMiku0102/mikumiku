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
    .then(response => response.json().then(data => {
        if (!response.ok) {
            console.error('Failed to add video:', data);
            alert('Failed to add video: ' + (data.message || 'Unknown error'));
        } else {
            alert('Video added successfully');
            document.getElementById('video-form').reset();
        }
    }))
    .catch(error => {
        console.error('Error:', error);
        alert('Failed to add video');
    });
});

document.getElementById('logout').addEventListener('click', function() {
    localStorage.removeItem('token');
    window.location.href = 'admin-login.html';
});
