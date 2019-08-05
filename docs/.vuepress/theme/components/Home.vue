<template>
  <main class="home" aria-labelledby="main-title">
    <header class="hero">
      <div class="section">
        <div class="content">
          <h1 v-if="data.heroText !== null" id="main-title">{{ data.heroText || $title || 'Hello' }}</h1>

          <p
            class="description"
          >{{ data.tagline || $description || 'Welcome to your VuePress site' }}</p>

          <p class="action" v-if="data.actionText && data.actionLink">
            <NavLink class="action-button" :item="actionLink" />
          </p>
        </div>

        <video class="media" autoplay loop muted playsinline>
          <source
            v-if="data.heroImage"
            :src="$withBase(data.heroImage)"
            :alt="data.heroAlt "
            type="video/mp4"
          />Your browser does not support the video tag.
        </video>
      </div>
    </header>

    <div class v-if="data.features && data.features.length">
      <div class="features section" v-for="(feature, index) in data.features" :key="index">
        <div class="feature">
          <img class="media" :src="$withBase(feature.src)" />
          <div class="content">
            <h2>{{ feature.title }}</h2>
            <p>{{ feature.text }}</p>
          </div>
        </div>
      </div>
    </div>
    <!-- triples -->
    <div class v-if="data.triples && data.triples.length">
      <div class="triples">
        <div class="feature">
          <div class="content" v-for="(feature, index) in data.triples" :key="index">
            <img class="media" :src="$withBase(feature.src)" />
            <h2>{{ feature.title }}</h2>
            <p>{{ feature.text }}</p>
          </div>
        </div>
      </div>
    </div>
    <Content class="theme-default-content custom" />

    <div class="footer" v-if="data.footer">{{ data.footer }}</div>
  </main>
</template>

<script>
import NavLink from "@theme/components/NavLink.vue";

export default {
  components: { NavLink },

  computed: {
    data() {
      return this.$page.frontmatter;
    },

    actionLink() {
      return {
        link: this.data.actionLink,
        text: this.data.actionText
      };
    }
  }
};
</script>

<style lang="stylus">
.home {
  padding: $navbarHeight 0 0;

  .hero {
    background-color: $accentColor;
    padding-top: 96pt - $navbarHeight;
    padding-bottom: 96pt;

    .section {
      padding: 0pt 0;
      margin: 0 auto;
      max-width: $contentWidth;
      justify-content: space-between;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      flex-direction: row;

      // flex-flow: column wrap;
      .media {
        padding: 0 20px;
        flex: 1;
        max-width: 45%;
        align-items: center;
      }

      .content {
        flex: 1;
        padding: 0 20px;

        h1 {
          text-align: left;
          margin-left: auto;
          margin-right: auto;
          font-size: 3.2rem;
          font-weight: 600;
          border-bottom: none;
          padding-bottom: 0;
          color: #ffffff;
        }

        .description {
          text-align: left;
          margin-left: auto;
          margin-right: auto;
          font-weight: 300;
          color: #ffffff;
          font-size: 1.5rem;
          line-height: 1.3;
        }

        .action-button {
          display: inline-block;
          font-size: 1.2rem;
          color: #fff;
          background-color: $accentColor;
          padding: 0.8rem 1.6rem;
          border-radius: 4px;
          transition: background-color 0.1s ease;
          box-sizing: border-box;
          border-bottom: 1px solid darken($accentColor, 10%);

          &:hover {
            background-color: lighten($accentColor, 10%);
          }
        }
      }
    }
  }
}

.triples {
  display: flex;
  flex-wrap: wrap;
  margin: 0 auto;
  padding: 32pt 0;
  background-color: $section-color;

  .feature {
    padding: 92pt 0;
    margin: 0 auto;
    max-width: $contentWidth;
    display: flex;
    justify-content: space-between;

    // flex-wrap: wrap;
    .content {
      display: flex;
      flex-direction: column;
      align-items: center;
      max-width: 100%;
      padding-left: 15px;

      .media {
        max-height: 150px;
      }

      h2 {
        padding: 10pt 0;
        display: flex;
        font-weight: 500;
        border-bottom: none;
        padding-bottom: 0;
        color: $headerColor;
      }

      p {
        text-align: left;
        margin-left: auto;
        margin-right: auto;
        font-weight: 400;
        color: $textColor;
      }
    }
  }
}

.features {
  background-color: #ffffff;
  padding: 72pt 0;
  display: flex;
  flex-wrap: wrap;
  margin: 0 auto;

  &:nth-child(even) {
    background-color: $section-color;
    border-top: 1px solid darken($section-color, 10%);
    border-bottom: 1px solid darken($section-color, 10%);

    .feature {
      .media {
        order: 1;
      }

      .content {
        order: 2;
      }
    }
  }

  .feature {
    padding: 0pt 0;
    margin: 0 auto;
    max-width: $contentWidth;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-direction: row;
    flex-wrap: wrap;

    .media {
      padding: 0 20px;
      max-height: 400px;
      max-width: 45%;
      flex: 1;
      order: 2;
    }

    .content {
      padding: 0 10px;
      max-width: 55%;
      order: 1;
      flex: 1;

      h2 {
        font-size: 2.4rem;
        font-weight: 600;
        border-bottom: none;
        padding-bottom: 0;
        color: $headerColor;
      }

      p {
        font-size: 1.2rem;
        text-align: left;
        margin-left: auto;
        margin-right: auto;
        font-weight: 400;
        color: $textColor;
      }
    }
  }

  .footer {
    padding: 2.5rem;
    border-top: 1px solid $borderColor;
    text-align: center;
    color: lighten($textColor, 25%);
  }
}

@media (max-width: $MQMobile) {
  .home {
    .feature {
      flex-direction: column;
    }

    .hero {
      padding-top: 20pt;

      .section {
        flex-direction: column;

        .media {
          max-width: 90%;
        }
      }
    }
  }
}

@media (max-width: $MQMobileNarrow) {
  .home {
    // padding-left: 0.5rem;
    // padding-right: 0.5rem;
    .hero {
      padding-top: 20pt;

      .section {
        flex-direction: column;

        .media {
          max-width: 90%;
        }
      }

      h1 {
        font-size: 2rem;
      }

      h1, .description, .action {
        margin: 1.2rem auto;
      }

      .description {
        font-size: 1.2rem;
      }

      .action-button {
        font-size: 1rem;
        padding: 0.6rem 1.2rem;
      }
    }

    .feature {
      h2 {
        font-size: 1.25rem;
      }
    }
  }
}
</style>
