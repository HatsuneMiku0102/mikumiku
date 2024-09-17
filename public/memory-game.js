document.addEventListener('DOMContentLoaded', () => {
    const cardArray = [
        { name: 'symbol1', symbol: '🍎' },
        { name: 'symbol1', symbol: '🍎' },
        { name: 'symbol2', symbol: '🍌' },
        { name: 'symbol2', symbol: '🍌' },
        { name: 'symbol3', symbol: '🍇' },
        { name: 'symbol3', symbol: '🍇' },
        { name: 'symbol4', symbol: '🍉' },
        { name: 'symbol4', symbol: '🍉' }
    ];

    
    cardArray.sort(() => 0.5 - Math.random());

    const gameBoard = document.getElementById('game-board');
    const gameStatus = document.getElementById('game-status');
    let chosenCards = [];
    let chosenCardsIds = [];
    let matchedCards = [];
    let canClick = true; // 

    function createBoard() {
        for (let i = 0; i < cardArray.length; i++) {
            const card = document.createElement('div');
            card.setAttribute('class', 'card');
            card.setAttribute('data-id', i);
            card.innerHTML = '<span class="symbol">' + cardArray[i].symbol + '</span>';
            card.addEventListener('click', flipCard);
            gameBoard.appendChild(card);
        }
    }

    function flipCard() {
        if (!canClick) return; 

        let cardId = this.getAttribute('data-id');
        if (chosenCardsIds.includes(cardId) || matchedCards.includes(cardId)) {
            return;
        }

        chosenCards.push(cardArray[cardId].name);
        chosenCardsIds.push(cardId);
        this.classList.add('flipped');

        if (chosenCards.length === 2) {
            canClick = false; 
            setTimeout(checkForMatch, 500);
        }
    }

    function checkForMatch() {
        const cards = document.querySelectorAll('.card');
        const optionOneId = chosenCardsIds[0];
        const optionTwoId = chosenCardsIds[1];

        if (chosenCards[0] === chosenCards[1]) {
            matchedCards.push(optionOneId, optionTwoId);
            if (matchedCards.length === cardArray.length) {
                gameStatus.textContent = 'Congratulations! You matched all the cards.';
                setTimeout(() => {
                  
                    document.getElementById('game-modal').style.display = 'none';
                    document.getElementById('main-content').style.display = 'block';
                }, 2000);
            }
        } else {
            setTimeout(() => {
                cards[optionOneId].classList.remove('flipped');
                cards[optionTwoId].classList.remove('flipped');
            }, 500);
        }

        chosenCards = [];
        chosenCardsIds = [];
        canClick = true; 
    }

    createBoard();
});
