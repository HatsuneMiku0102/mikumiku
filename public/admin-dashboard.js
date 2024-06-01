document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', function(event) {
            event.preventDefault();

            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;

            fetch('/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            })
            .then(response => response.json())
            .then(data => {
                if (data.auth) {
                    localStorage.setItem('token', data.token);
                    window.location.href = '/admin-dashboard.html';
                } else {
                    alert(data.message);
                }
            })
            .catch(error => {
                console.error('Error:', error);
            });
        });
    }

    const logoutButton = document.getElementById('logout');
    if (logoutButton) {
        logoutButton.addEventListener('click', function() {
            localStorage.removeItem('token');
            window.location.href = '/admin-login.html';
        });
    }

    fetchVideos();

    function fetchVideos() {
        const token = localStorage.getItem('token');
        fetch('/api/videos', {
            method: 'GET',
            headers: {
                'Authorization': token
            }
        })
        .then(response => response.json())
        .then(videos => {
            renderVideos(videos);
        })
        .catch(error => {
            console.error('Error loading videos:', error);
        });
    }
});

function renderVideos(videos) {
    const videoContainer = document.getElementById('video-container');
    videoContainer.innerHTML = '';

    if (videos.length === 0) {
        videoContainer.innerHTML = '<p>No videos available</p>';
        return;
    }

    videos.forEach(video => {
        const videoItem = document.createElement('div');
        videoItem.classList.add('video-item');
        videoItem.setAttribute('data-id', video.id);
        videoItem.innerHTML = `
            <iframe width="720" height="405" src="${video.url}" frameborder="0" allowfullscreen></iframe>
            <h3>${video.title}</h3>
            <p class="video-description">${video.description}</p>
            <p class="video-category"><strong>Category:</strong> ${video.category}</p>
            <button class="delete-button" data-id="${video.id}">Delete</button>
        `;
        videoContainer.appendChild(videoItem);
    });

    document.querySelectorAll('.delete-button').forEach(button => {
        button.addEventListener('click', function() {
            const videoId = this.getAttribute('data-id');
            deleteVideo(videoId);
        });
    });
}

function deleteVideo(videoId) {
    const token = localStorage.getItem('token');
    fetch(`/api/videos/${videoId}`, {
        method: 'DELETE',
        headers: {
            'Authorization': token
        }
    })
    .then(response => {
        if (!response.ok) {
            console.error('Failed to delete video:', response);
            throw new Error('Failed to delete video');
        }
        return response.json();
    })
    .then(() => {
        alert('Video deleted successfully');
        const videoItem = document.querySelector(`.video-item[data-id="${videoId}"]`);
        if (videoItem) {
            videoItem.remove();
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Failed to delete video');
    });
}
