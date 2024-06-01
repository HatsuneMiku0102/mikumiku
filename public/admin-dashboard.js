document.addEventListener('DOMContentLoaded', function() {
    const token = localStorage.getItem('token');
    if (!token) {
        window.location.href = 'admin-login.html';
        return;
    }

    function fetchVideos() {
        fetch('/api/videos', {
            headers: {
                'x-access-token': token
            }
        })
        .then(response => {
            if (!response.ok) {
                if (response.status === 401) {
                    window.location.href = 'admin-login.html';
                }
                throw new Error('Failed to fetch videos');
            }
            return response.json();
        })
        .then(videos => {
            renderVideos(videos);
        })
        .catch(error => {
            console.error('Error loading videos:', error);
            document.getElementById('error-message').textContent = 'Error loading videos: ' + error.message;
        });
    }

    function renderVideos(videos) {
        const videoContainer = document.getElementById('video-container');
        if (!videoContainer) {
            console.error('Error: video-container element not found.');
            return;
        }

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
        fetch(`/api/videos/${videoId}`, {
            method: 'DELETE',
            headers: {
                'x-access-token': token
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

    document.getElementById('video-form').addEventListener('submit', function(event) {
        event.preventDefault();

        const title = document.getElementById('video-title').value;
        const url = document.getElementById('video-url').value.replace('youtu.be', 'youtube.com/embed');
        const description = document.getElementById('video-description').value;
        const category = document.getElementById('video-category').value;

        const video = { title, url, description, category };

        fetch('/api/videos', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-access-token': token
            },
            body: JSON.stringify(video)
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(data => {
                    console.error('Failed to add video:', data);
                    alert('Failed to add video: ' + (data.message || 'Unknown error'));
                    throw new Error('Failed to add video');
                });
            }
            return response.json();
        })
        .then(data => {
            alert('Video added successfully');
            document.getElementById('video-form').reset();
            fetchVideos();
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Failed to add video');
        });
    });

    document.getElementById('logout').addEventListener('click', function() {
        fetch('/logout', {
            method: 'POST'
        })
        .then(response => response.json())
        .then(() => {
            localStorage.removeItem('token');
            window.location.href = 'admin-login.html';
        })
        .catch(error => {
            console.error('Error:', error);
        });
    });

    fetchVideos();
});
