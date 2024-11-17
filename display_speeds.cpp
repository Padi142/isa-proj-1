// Matyáš Krejza
// xkrejz07

#include "display_speeds.hpp"

#include <ncurses.h>

#include <algorithm>
#include <chrono>
#include <ranges>
#include <string>
#include <thread>

#include "connections.hpp"

using namespace std;
using namespace std::chrono;

// Helper function
time_point<steady_clock> current_time() { return steady_clock::now(); }

// Sort connections by the total number of bytes sent and received
void sort_connections_by_speed() {
  ranges::sort(connections, [](const Connection &a, const Connection &b) { return (a.bytes_sent + a.bytes_received) > (b.bytes_sent + b.bytes_received); });
}

// Sort connections by the number of packets
void sort_connections_by_packets() {
  ranges::sort(connections, [](const Connection &a, const Connection &b) { return a.packets > b.packets; });
}

string format_speed(double bytes_per_sec) {
  const char *units[] = {"b/s", "Kb/s", "Mb/s", "Gb/s"};
  int unit = 0;
  double bits_per_sec = bytes_per_sec * 8;

  // Convert bits to a more readable unit
  while (bits_per_sec >= 1000.0 && unit < 3) {
    bits_per_sec /= 1000.0;
    unit++;
  }

  // Write the speed to a buffer and return it
  char buffer[32];
  snprintf(buffer, sizeof(buffer), "%.1f %s", bits_per_sec, units[unit]);
  return string(buffer);
}

// Function to display connection speeds
void display_transfer_speeds() {
  // Static variables to store the last time we displayed the speeds
  static auto last_time = current_time();
  auto now = current_time();

  // Calculate the elapsed time since the last display
  double elapsed_seconds = duration<double>(now - last_time).count();
  last_time = now;

  // Print header
  mvprintw(0, 0, "Network Traffic Monitor");
  mvprintw(2, 0, "%-39s %-6s  %-39s %-6s  %-4s  %-12s %-12s  %-8s", "Source IP", "Port", "Dest IP", "Port", "Proto", "Send", "Recv", "Packets");
  mvprintw(3, 0, "----------------------------------------------------------------------------------------------------------------------------------");

  int row = 4;
  int index = 0;
  for (auto &conn : connections) {
    // Print top 10 connections
    if (index >= 10) break;
    double send_speed = conn.bytes_sent / elapsed_seconds;
    double recv_speed = conn.bytes_received / elapsed_seconds;

    // Format the speeds
    string send_formatted = format_speed(send_speed);
    string recv_formatted = format_speed(recv_speed);

    mvprintw(row, 0, "%-39s %-6d  %-39s %-6d  %-4s  %-12s %-12s  %-8lu", conn.src_ip.c_str(), conn.src_port, conn.dst_ip.c_str(), conn.dst_port,
             conn.protocol.c_str(), send_formatted.c_str(), recv_formatted.c_str(), conn.packets);
    row++;
    index++;
  }

  // Print footer
  mvprintw(row + 1, 0, "----------------------------------------------------------------------------------------------------------------------------------");
}

[[noreturn]] void display_speeds(char sort_mode) {
  while (true) {
    clear();
    // Sort the connections based on the sort mode
    if (sort_mode == 'b') {
      sort_connections_by_speed();
    } else if (sort_mode == 'p') {
      sort_connections_by_packets();
    }

    display_transfer_speeds();
    refresh();
    connections.clear();  // Reset stats periodically
    this_thread::sleep_for(chrono::seconds(1));
  }
}