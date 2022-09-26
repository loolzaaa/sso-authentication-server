function updateTime() {
    let now = new Date();
    let time = now.toLocaleString('ru', {hour: 'numeric', minute: 'numeric'});
    document.getElementById('time').innerText = time;
}
updateTime();
setInterval(updateTime, 1000);


let resizeEvent = _.debounce(() => {
    let isMobileView = document.documentElement.clientWidth < 769 ? true : false;
    document.getElementById('time-block').style.display = isMobileView ? 'none' : 'block';

}, 100);
window.addEventListener("resize", resizeEvent);


//-------------- Toggle scroll by mouse with click and drag
var curYPos, curXPos, curDown;
var scrollFire = function(e) {
    if (curDown) {
        let scrollLeft = document.documentElement.scrollLeft || document.body.scrollLeft || 0;
        let scrollTop = document.documentElement.scrollTop || document.body.scrollTop || 0;
        window.scrollTo(scrollLeft + (curXPos - e.pageX), scrollTop + (curYPos - e.pageY));
    }
}
var scrollStart = function(e) {
    curYPos = e.pageY;
    curXPos = e.pageX;
    curDown = true;
}
var scrollEnd = function(e) {
    curDown = false;
}
function toggleDragScroll() {
	if (isTouchDevice) {
		window.addEventListener('mousemove', scrollFire, true);
		window.addEventListener('mousedown', scrollStart, true);
		window.addEventListener('mouseup', scrollEnd, true);
	} else {
		window.removeEventListener('mousemove', scrollFire, true);
		window.removeEventListener('mousedown', scrollStart, true);
		window.removeEventListener('mouseup', scrollEnd, true);
	}
}
//--------------------------------------------------------------
let isTouchDevice = false;
function changeTouchStatus() {
    isTouchDevice = !isTouchDevice;
    if (isTouchDevice) {
        document.getElementById('touch-keyboard').style.display = 'block';
        document.getElementById('not-touch-keyboard').style.display = 'none';
    } else {
        document.getElementById('touch-keyboard').style.display = 'none';
        document.getElementById('not-touch-keyboard').style.display = 'block';
    }
    toggleDragScroll();
}


document.addEventListener('DOMContentLoaded', function () {
    var $navbarBurgers = Array.prototype.slice.call(document.querySelectorAll('.navbar-burger'), 0);
    if ($navbarBurgers.length > 0) {
        $navbarBurgers.forEach(function ($el) {
            $el.addEventListener('click', function () {
                var target = $el.dataset.target;
                var $target = document.getElementById(target);
                $el.classList.toggle('is-active');
                $target.classList.toggle('is-active');
            });
      });
    }
});

function getFingerprint() {
    return new Promise((resolve, reject) => {
        async function getHash () {
            const options = {
                excludes: {
                    plugins: true,
                    localStorage: true,
                    adBlock: true,
                    screenResolution: true,
                    availableScreenResolution: true,
                    enumerateDevices: true,
                    pixelRatio: true,
                    doNotTrack: true
                }
            }

            try {
                const components = await Fingerprint2.getPromise(options);
                const values = components.map(component => component.value);
                return String(Fingerprint2.x64hash128(values.join(''), 31));
            } catch (e) {
                reject(e);
            }
        }

        if (window.requestIdleCallback) {
            requestIdleCallback(async () => resolve(await getHash()));
        } else {
            setTimeout(async () => resolve(await getHash()), 500);
        }
    });
}