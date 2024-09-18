document.addEventListener('DOMContentLoaded', () => {
    const commentForm = document.getElementById('comment-form');
    const commentsList = document.getElementById('comments-list');


    fetch('/api/comments')
        .then(response => response.json())
        .then(comments => {
            renderComments(comments);
        })
        .catch(error => {
            console.error('Error loading comments:', error);
        });


    commentForm.addEventListener('submit', event => {
        event.preventDefault();
        const username = document.getElementById('username').value;
        const comment = document.getElementById('comment').value;

        fetch('/api/comments', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, comment })
        })
        .then(response => response.json())
        .then(newComment => {
         
            renderComments([newComment]);
            commentForm.reset();
        })
        .catch(error => {
            console.error('Error submitting comment:', error);
            alert('Failed to submit comment');
        });
    });

  
    function renderComments(comments) {
        comments.forEach(comment => {
            const commentItem = document.createElement('div');
            commentItem.classList.add('comment-item');
            commentItem.innerHTML = `<strong>${comment.username}</strong>: ${comment.comment}`;
            commentsList.appendChild(commentItem);
        });
    }
});
