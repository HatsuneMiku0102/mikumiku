
console.log("Welcome to MikuMiku <3");

document.addEventListener('DOMContentLoaded', function() {
    const videoContainer = document.getElementById('video-container');

    fetch('/api/videos')
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(videos => {
            if (videos && videos.length) {
                videoContainer.innerHTML = ''; 

                videos.forEach(video => {
                    const videoItem = document.createElement('div');
                    videoItem.classList.add('video-item');
                    videoItem.innerHTML = `
                        <iframe width="560" height="315" src="${video.url}" frameborder="0" allowfullscreen></iframe>
                        <h3>${video.title}</h3>
                        <p class="video-description">${video.description}</p>
                    `;
                    videoContainer.appendChild(videoItem);
                });
            } else {
                videoContainer.innerHTML = '<p>No videos available</p>';
            }
        })
        .catch(error => {
            console.error('Error fetching video data:', error);
            videoContainer.innerHTML = '<p>Error loading videos</p>';
        });
});


document.addEventListener('DOMContentLoaded', function () {
    const textElement = document.getElementById('typing-text');
    const text = 'MikuMiku';
    const typingSpeed = 200;

    let index = 0;

    function typeCharacter() {
        if (index < text.length) {
            textElement.innerHTML += text[index];
            index++;
            setTimeout(typeCharacter, typingSpeed);
        }
    }

    typeCharacter();
});

document.addEventListener('DOMContentLoaded', function () {
    const textElement = document.getElementById('fancy-title');
    const text = 'Hand Picked Vocaloid Tracks <3';
    const typingSpeed = 300;

    const words = text.split(' ');
    let wordIndex = 0;

    function typeWord() {
        if (wordIndex < words.length) {
            textElement.innerHTML += (wordIndex > 0 ? ' ' : '') + words[wordIndex];
            wordIndex++;
            setTimeout(typeWord, typingSpeed);
        }
    }

    typeWord();
});

document.querySelector('.fancy-title').addEventListener('mouseover', function () {
    for (let i = 0; i < 50; i++) {
        createBlossom();
    }
});

function createBlossom() {
    const blossom = document.createElement('div');
    blossom.classList.add('blossom');
    blossom.style.left = `${Math.random() * 100}%`;
    blossom.style.animationDuration = `${Math.random() * 5 + 3}s`;
    document.body.appendChild(blossom);

    setTimeout(() => {
        blossom.remove();
    }, 8000);
}

fetch('/api/videos')
    .then(response => {
        if (!response.ok) {
            throw new Error('Failed to fetch videos');
        }
        return response.json();
    })
    .then(data => {
        const videoContainer = document.getElementById('video-container');
        if (data && data.length) {
            data.forEach(video => {
                const videoItem = document.createElement('div');
                videoItem.classList.add('video-item');
                videoItem.innerHTML = `
                    <iframe width="560" height="315" src="${video.url}" frameborder="0" allowfullscreen></iframe>
                    <h3>${video.title}</h3>
                    <p>${video.description}</p>
                `;
                videoContainer.appendChild(videoItem);
            });
        } else {
            videoContainer.innerHTML = '<p>No videos available</p>';
        }
    })
    .catch(error => {
        console.error('Error fetching video data:', error);
        document.getElementById('video-container').innerHTML = '<p>Error loading videos.</p>';
    });
