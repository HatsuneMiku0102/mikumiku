document.addEventListener('DOMContentLoaded', function() {

    const socket = io(); // Connect to the server using Socket.IO

    // Listen for real-time updates for active users
    socket.on('activeUsersUpdate', (data) => {
        document.getElementById('active-users-count').innerText = `Currently Active Users: ${data.count}`;
    });

    // Fetch the list of videos from the server
    fetch('/api/videos')
        .then(response => {
            if (!response.ok) {
                if (response.status === 401) {
                    return response.json().then(data => {
                        window.location.href = data.redirect;
                    });
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
        });

    // Fetch the list of comments from the server
    fetch('/api/comments')
        .then(response => response.json())
        .then(comments => {
            renderComments(comments);
        })
        .catch(error => {
            console.error('Error loading comments:', error);
        });

    // Function to render comments
    function renderComments(comments) {
        const commentContainer = document.getElementById('comment-container');
        commentContainer.innerHTML = '';

        comments.forEach(comment => {
            const commentItem = document.createElement('div');
            commentItem.innerHTML = `
                <strong>${comment.username}</strong>: ${comment.comment}
                <button class="delete-comment" data-id="${comment._id}">Delete</button>
            `;
            commentContainer.appendChild(commentItem);
        });

        document.querySelectorAll('.delete-comment').forEach(button => {
            button.addEventListener('click', function() {
                const commentId = this.getAttribute('data-id');
                deleteComment(commentId);
            });
        });
    }

    // Function to delete a comment
    function deleteComment(id) {
        fetch(`/api/comments/${id}`, {
            method: 'DELETE'
        })
        .then(response => {
            if (response.ok) {
                alert('Comment deleted');
                document.querySelector(`button[data-id="${id}"]`).parentElement.remove();
            } else {
                alert('Failed to delete comment');
            }
        })
        .catch(error => {
            console.error('Error deleting comment:', error);
            alert('Failed to delete comment');
        });
    }

    // Handle the form submission for adding new videos
    const videoForm = document.getElementById('video-form');
    if (videoForm) {
        videoForm.addEventListener('submit', function(event) {
            event.preventDefault();

            const title = document.getElementById('video-title').value;
            const url = document.getElementById('video-url').value.replace('youtu.be', 'youtube.com/embed');
            const description = document.getElementById('video-description').value;
            const category = document.getElementById('video-category').value;

            const video = { title, url, description, category };

            fetch('/api/videos', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(video)
            })
            .then(response => {
                if (!response.ok) {
                    if (response.status === 401) {
                        return response.json().then(data => {
                            window.location.href = data.redirect;
                        });
                    }
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
                videoForm.reset();

                fetch('/api/videos')
                    .then(response => response.json())
                    .then(videos => {
                        if (!Array.isArray(videos)) {
                            throw new Error('Invalid response format');
                        }
                        renderVideos(videos);
                    });
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Failed to add video');
            });
        });
    }

    // Handle the logout process
    const logoutButton = document.getElementById('logout');
    if (logoutButton) {
        logoutButton.addEventListener('click', function() {
            fetch('/logout', {
                method: 'POST'
            })
            .then(() => {
                document.cookie = 'token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
                window.location.href = '/admin-login.html';
            })
            .catch(error => {
                console.error('Error:', error);
            });
        });
    }

    // Handle video category filtering
    document.querySelector('.category-bar').addEventListener('click', function(event) {
        if (event.target.tagName === 'BUTTON') {
            const category = event.target.getAttribute('data-category');
            fetch('/api/videos')
                .then(response => response.json())
                .then(videos => {
                    if (!Array.isArray(videos)) {
                        throw new Error('Invalid response format');
                    }
                    const filteredVideos = category === 'all' ? videos : videos.filter(video => video.category === category);
                    renderVideos(filteredVideos);
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('Failed to filter videos');
                });
        }
    });
});

// Function to render the list of videos
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

    // Add event listeners for delete buttons
    document.querySelectorAll('.delete-button').forEach(button => {
        button.addEventListener('click', function() {
            const videoId = this.getAttribute('data-id');
            deleteVideo(videoId);
        });
    });
}

// Function to delete a video
function deleteVideo(videoId) {
    fetch(`/api/videos/${videoId}`, {
        method: 'DELETE'
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
