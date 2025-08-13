// ===================== Revenue Chart Start =============================== 
function createChartTwo(chartId, color1, color2) {
    var options = {
        series: [{
            name: "series1",
            data: [6, 20, 15, 48, 28, 55, 28, 52, 25, 32, 15, 25]
        }, {
            name: "series2",
            data: [0, 8, 4, 36, 16, 42, 16, 40, 12, 24, 4, 12]
        }],
        legend: {
            show: false
        },
        chart: {
            type: "area",
            width: "100%",
            height: 150,
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
                opacityFrom: [0.4, 0.6], // Starting opacity for both colors
                opacityTo: [0.3, 0.3], // Ending opacity for both colors
                stops: [0, 100],
            },
        },
        // markers: {
        //     colors: [color1, color2], // Use two colors for the markers
        //     strokeWidth: 3,
        //     size: 0,
        //     hover: {
        //         size: 10
        //     }
        // },

        markers: {
            colors: [color1, color2],
            strokeWidth: 2,
            size: 0,
            hover: {
                size: 8
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

createChartTwo("revenueChart", "#CD20F9", "#6593FF");
// ===================== Revenue Chart End =============================== 

// ================================ Bar chart Start ================================ 
var options = {
    series: [{
        name: "Sales",
        data: [{
            x: "Sun",
            y: 15,
        }, {
            x: "Mon",
            y: 12,
        }, {
            x: "Tue",
            y: 18,
        }, {
            x: "Wed",
            y: 20,
        }, {
            x: "Thu",
            y: 13,
        }, {
            x: "Fri",
            y: 16,
        }, {
            x: "Sat",
            y: 6,
        }]
    }],
    chart: {
        type: "bar",
        height: 200,
        toolbar: {
            show: false
        },
    },
    plotOptions: {
        bar: {
            borderRadius: 6,
            horizontal: false,
            columnWidth: 24,
            columnWidth: "40%",
            endingShape: "rounded",
        }
    },
    dataLabels: {
        enabled: false
    },
    fill: {
        type: "gradient",
        colors: ["#dae5ff"], // Set the starting color (top color) here
        gradient: {
            shade: "light", // Gradient shading type
            type: "vertical", // Gradient direction (vertical)
            shadeIntensity: 0.5, // Intensity of the gradient shading
            gradientToColors: ["#dae5ff"], // Bottom gradient color (with transparency)
            inverseColors: false, // Do not invert colors
            opacityFrom: 1, // Starting opacity
            opacityTo: 1, // Ending opacity
            stops: [0, 100],
        },
    },
    grid: {
        show: false,
        borderColor: "#D1D5DB",
        strokeDashArray: 4, // Use a number for dashed style
        position: "back",
        padding: {
            top: -10,
            right: -10,
            bottom: -10,
            left: -10
        }
    },
    xaxis: {
        type: "category",
        categories: ["2hr", "4hr", "6hr", "8hr", "10hr", "12hr", "14hr"]
    },
    yaxis: {
        show: false,
    },
};

var chart = new ApexCharts(document.querySelector("#barChart"), options);
chart.render();
// ================================ Bar chart End ================================ 

// ================================ J Vector Map Start ================================ 
$("#world-map").vectorMap({
    map: "world_mill_en",
    backgroundColor: "transparent",
    borderColor: "#fff",
    borderOpacity: 0.25,
    borderWidth: 0,
    color: "#000000",
    regionStyle: {
        initial: {
            fill: "#D1D5DB"
        }
    },
    markerStyle: {
        initial: {
            r: 5,
            "fill": "#fff",
            "fill-opacity": 1,
            "stroke": "#000",
            "stroke-width": 1,
            "stroke-opacity": 0.4
        },
    },
    markers: [{
            latLng: [35.8617, 104.1954],
            name: "China : 250"
        },

        {
            latLng: [25.2744, 133.7751],
            name: "AustrCalia : 250"
        },

        {
            latLng: [36.77, -119.41],
            name: "USA : 82%"
        },

        {
            latLng: [55.37, -3.41],
            name: "UK   : 250"
        },

        {
            latLng: [25.20, 55.27],
            name: "UAE : 250"
        }
    ],

    series: {
        regions: [{
            values: {
                "US": "#487FFF ",
                "SA": "#487FFF",
                "AU": "#487FFF",
                "CN": "#487FFF",
                "GB": "#487FFF",
            },
            attribute: "fill"
        }]
    },
    hoverOpacity: null,
    normalizeFunction: "linear",
    zoomOnScroll: false,
    scaleColors: ["#000000", "#000000"],
    selectedColor: "#000000",
    selectedRegions: [],
    enableZoom: false,
    hoverColor: "#fff",
});
// ================================ J Vector Map End ================================ 


// ================================ Users Overview Donut chart Start ================================ 
var options = {
    series: [500, 500, 500],
    colors: ["#FF9F29", "#487FFF", "#45B369"],
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
