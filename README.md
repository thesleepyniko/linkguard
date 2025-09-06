
# LinkGuard

![Athena Award Badge](https://img.shields.io/endpoint?url=https%3A%2F%2Faward.athena.hackclub.com%2Fapi%2Fbadge)

## What is this?

Hi! This is a slack bot called LinkGuard. It's primary purpose is to scan for malicious links in channels it has been added to and warn if they're malicious! It's not 100% perfect due to relying on Google WebRiskAPI (and also potentially hitting quota :pf:)

## Why did you make this?

It was originally for converge, but then I realized even after converge had ended that I really wanted something like this to exist! I also realized that a lot of other platforms do this kind of basic scanning (like Discord iirc), but slack doesn't! So I wanted to implement it!

## How did you make this?

This project was made fully in python! Specifically, python3! It uses a google API to pull a database that has some prefixes that links are first matched with, and if a match is found, it will then query the API to confirm before giving a result! If you're wondering what I did to learn and implement, mostly documentation reading and trial and error!

## What'd you struggle with and what'd you learn?

everything :sob: /silly
But honestly, mostly making my checking up to spec, as the API is super strict and also you have to hash the links a certian way! Otherwise, it was really smooth and I now love Bolt for Python! I learned a lot of Google API stuff along the way and just general troubleshooting skills :3

