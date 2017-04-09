drop table if exists tokens;
create table tokens (
  session_id text not null,
  service_id text not null,
  token text not null,
  origin text not null,
  created text not null
);