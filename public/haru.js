    document.addEventListener('DOMContentLoaded', function () {
        const chatBox = document.getElementById('chat-box');
        const chatTrigger = document.getElementById('haru-chat-trigger');
        const closeChatButton = document.getElementById('close-chat');
        const personalityCircle = document.getElementById('personalityCircle');
    
        // Open the chat box when Haru's personality circle or the trigger button is clicked
        const openChat = () => {
            chatBox.style.display = 'flex'; // Show the chat box
        };
    
        // Close the chat box when the close button is clicked
        const closeChat = () => {
            chatBox.style.display = 'none'; // Hide the chat box
        };
    
        // Add event listener for the Haru circle and trigger button
        chatTrigger.addEventListener('click', openChat);
        personalityCircle.addEventListener('click', openChat);
    
        // Add event listener for the close button
        closeChatButton.addEventListener('click', closeChat);
    });


    // Send message when the send button is clicked
    sendMessageButton.addEventListener('click', async function () {
        const userMessage = chatInput.value.trim();
        if (userMessage) {
            addMessageToChat(userMessage, 'user-message');
            chatInput.value = '';
            const botResponse = await getGPTResponse(userMessage);
            addMessageToChat(botResponse, 'bot-message');
        }
    });

    // Add a new message to the chat window
    function addMessageToChat(message, className) {
        const messageElement = document.createElement('div');
        messageElement.classList.add('message', className);
        messageElement.textContent = message;
        chatContent.appendChild(messageElement);
        chatContent.scrollTop = chatContent.scrollHeight; // Scroll to the bottom
    }

    // Mock GPT-4 API call (replace with actual call using OpenAI API)
    async function getGPTResponse(message) {
        // Placeholder - here you can integrate the OpenAI API using fetch or axios
        return new Promise(resolve => {
            setTimeout(() => {
                resolve("This is a response from Haru via GPT-4");
            }, 1000);
        });
    }
});
