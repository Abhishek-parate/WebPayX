
// ===================== Average Enrollment Rate Start =============================== 
function createChartTwo(chartId, color1, color2) {
    var options = {
        series: [{
            name: "series1",
            data: [48, 35, 55, 32, 48, 30, 55, 50, 57]
        }, {
            name: "series2",
            data: [12, 20, 15, 26, 22, 60, 40, 48, 25]
        }],
        legend: {
            show: false
        },
        chart: {
            type: "area",
            width: "100%",
            height: 270,
            toolbar: {
                show: false
            },
            padding: {
                left: 0,
                right: 0,
                top: 0,
                bottom: 0
            }
        },
        dataLabels: {
            enabled: false
        },
        stroke: {
            curve: "smooth",
            width: 3,
            colors: [color1, color2], // Use two colors for the lines
            lineCap: "round"
        },
        grid: {
            show: true,
            borderColor: "#D1D5DB",
            strokeDashArray: 1,
            position: "back",
            xaxis: {
                lines: {
                    show: false
                }
            },
            yaxis: {
                lines: {
                    show: true
                }
            },
            row: {
                colors: undefined,
                opacity: 0.5
            },
            column: {
                colors: undefined,
                opacity: 0.5
            },
            padding: {
                top: -20,
                right: 0,
                bottom: -10,
                left: 0
            },
        },
        fill: {
            type: "gradient",
            colors: [color1, color2], // Use two colors for the gradient
            // gradient: {
            //     shade: "light",
            //     type: "vertical",
            //     shadeIntensity: 0.5,
            //     gradientToColors: [`${color1}`, `${color2}00`], // Bottom gradient colors with transparency
            //     inverseColors: false,
            //     opacityFrom: .6,
            //     opacityTo: 0.3,
            //     stops: [0, 100],
            // },
            gradient: {
                shade: "light",
                type: "vertical",
                shadeIntensity: 0.5,
                gradientToColors: [undefined, `${color2}00`], // Apply transparency to both colors
                inverseColors: false,
                opacityFrom: [0.4, 0.4], // Starting opacity for both colors
                opacityTo: [0.3, 0.3], // Ending opacity for both colors
                stops: [0, 100],
            },
        },
        markers: {
            colors: [color1, color2], // Use two colors for the markers
            strokeWidth: 3,
            size: 0,
            hover: {
                size: 10
            }
        },
        xaxis: {
            labels: {
                show: false
            },
            categories: ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
            tooltip: {
                enabled: false
            },
            labels: {
                formatter: function(value) {
                    return value;
                },
                style: {
                    fontSize: "14px"
                }
            }
        },
        yaxis: {
            labels: {
                formatter: function(value) {
                    return "$" + value + "k";
                },
                style: {
                    fontSize: "14px"
                }
            },
        },
        tooltip: {
            x: {
                format: "dd/MM/yy HH:mm"
            }
        }
    };

    var chart = new ApexCharts(document.querySelector(`#${chartId}`), options);
    chart.render();
}

createChartTwo("enrollmentChart", "#45B369", "#487fff");
// ===================== Average Enrollment Rate End =============================== 


// ================================ Users Overview Donut chart Start ================================ 
var options = {
    series: [500, 500, 500],
    colors: ["#FF9F29", "#487FFF", "#E4F1FF"],
    labels: ["Active", "New", "Total"],
    legend: {
        show: false
    },
    chart: {
        type: "donut",
        height: 270,
        sparkline: {
            enabled: true // Remove whitespace
        },
        margin: {
            top: 0,
            right: 0,
            bottom: 0,
            left: 0
        },
        padding: {
            top: 0,
            right: 0,
            bottom: 0,
            left: 0
        }
    },
    stroke: {
        width: 0,
    },
    dataLabels: {
        enabled: false
    },
    responsive: [{
        breakpoint: 480,
        options: {
            chart: {
                width: 200
            },
            legend: {
                position: "bottom"
            }
        }
    }],
};

var chart = new ApexCharts(document.querySelector("#userOverviewDonutChart"), options);
chart.render();
// ================================ Users Overview Donut chart End ================================ 

// ================================ Client Payment Status chart End ================================ 
var options = {
    series: [{
        name: "Net Profit",
        data: [44, 100, 40, 56, 30, 58, 50]
    }, {
        name: "Free Cash",
        data: [60, 120, 60, 90, 50, 95, 90]
    }],
    colors: ["#45B369", "#FF9F29"],
    labels: ["Active", "New", "Total"],

    legend: {
        show: false
    },
    chart: {
        type: "bar",
        height: 420,
        toolbar: {
            show: false
        },
    },
    grid: {
        show: true,
        borderColor: "#D1D5DB",
        strokeDashArray: 4, // Use a number for dashed style
        position: "back",
    },
    plotOptions: {
        bar: {
            borderRadius: 4,
            columnWidth: 8,
        },
    },
    dataLabels: {
        enabled: false
    },
    states: {
        hover: {
            filter: {
                type: "none"
            }
        }
    },
    stroke: {
        show: true,
        width: 0,
        colors: ["transparent"]
    },
    xaxis: {
        categories: ["Mon", "Tues", "Wed", "Thurs", "Fri", "Sat", "Sun"],
    },
    fill: {
        opacity: 1,
        width: 18,
    },
};

var chart = new ApexCharts(document.querySelector("#paymentStatusChart"), options);
chart.render();
// ================================ Client Payment Status chart End ================================ 

// ================================ Aminated Radial Progress Bar Start ================================ 
$("svg.radial-progress").each(function(index, value) {
    $(this).find($("circle.complete")).removeAttr("style");
});

// Activate progress animation on scroll
$(window).scroll(function() {
    $("svg.radial-progress").each(function(index, value) {
        // If svg.radial-progress is approximately 25% vertically into the window when scrolling from the top or the bottom
        if (
            $(window).scrollTop() > $(this).offset().top - ($(window).height() * 0.75) &&
            $(window).scrollTop() < $(this).offset().top + $(this).height() - ($(window).height() * 0.25)
        ) {
            // Get percentage of progress
            percent = $(value).data("percentage");
            // Get radius of the svg"s circle.complete
            radius = $(this).find($("circle.complete")).attr("r");
            // Get circumference (2πr)
            circumference = 2 * Math.PI * radius;
            // Get stroke-dashoffset value based on the percentage of the circumference
            strokeDashOffset = circumference - ((percent * circumference) / 100);
            // Transition progress for 1.25 seconds
            $(this).find($("circle.complete")).animate({
                "stroke-dashoffset": strokeDashOffset
            }, 1250);
        }
    });
}).trigger("scroll");
// ================================ Aminated Radial Progress Bar End ================================ 
